"""Bounded byte-range extraction with exact global threshold windows in DuckDB.

Unlike finite byte overlap, a global event-time window cannot miss a slow attack
at a range or file boundary. Candidate rows spill to disk, never to parent pipes.
"""
import argparse
import concurrent.futures
import hashlib
import json
import multiprocessing
import os
import time
import threading
from pathlib import Path

import psutil
import pyarrow as pa
import pyarrow.parquet as pq

from backend.rules import ROOT, RuleEngine
from backend.store import connect

SCHEMA = pa.schema([(k, pa.int64() if k in {'ts','first_ts','last_ts','bytes','count','stage_order','weight','offset','window','threshold'} else pa.string()) for k in (
    'host','user','src_ip','dst_ip','dst_port','new_user','ts','first_ts','last_ts','bytes','count','rule_id','rule_name',
    'technique','technique_name','tactic','kill_chain','stage_order','weight','file','offset','group_key','distinct_value','kind','window','threshold','alert_id')])
MAX_LINE = 1024 * 1024


def ranges(path, size=64*1024*1024):
    for f in sorted([path] if path.is_file() else (p for p in path.rglob('*') if p.is_file())):
        if f.suffix.lower() not in {'.log','.txt','.syslog',''}: continue
        stat = f.stat()
        for start in range(0, stat.st_size, size):
            yield (str(f.resolve()), start, min(start+size, stat.st_size), stat.st_size, stat.st_mtime_ns)


def scan_range(task):
    file, start, end, _, _, out, rules = task
    engine = RuleEngine(Path(rules))
    rows, lines, rejected = [], 0, 0
    writer = pq.ParquetWriter(out, SCHEMA, compression='zstd')
    try:
        with open(file, 'rb') as stream:
            if start:
                stream.seek(start-1)
                if stream.read(1) != b'\n': stream.readline(MAX_LINE+1)
            while stream.tell() < end:
                offset = stream.tell()
                line = stream.readline(MAX_LINE+1)
                if not line: break
                lines += 1
                if len(line) > MAX_LINE:
                    rejected += 1
                    while line and not line.endswith(b'\n'): line = stream.readline(MAX_LINE+1)
                    continue
                rows.extend(engine.candidates(line, file, offset))
                if len(rows) >= 8192:
                    writer.write_table(pa.Table.from_pylist(rows, schema=SCHEMA)); rows.clear()
            if rows: writer.write_table(pa.Table.from_pylist(rows, schema=SCHEMA))
    finally: writer.close()
    return {'parquet': out, 'lines': lines, 'oversized_lines': rejected, 'bytes': end-start}


def materialize(db, files):
    db.execute('CREATE OR REPLACE TEMP TABLE candidates AS SELECT * FROM read_parquet(?)', [files])
    db.execute('CREATE OR REPLACE TABLE alerts AS SELECT * FROM candidates WHERE kind=\'match\'')
    rules = db.execute("SELECT DISTINCT rule_id,kind,\"window\",threshold FROM candidates WHERE kind!='match'").fetchall()
    for rule_id, kind, window, threshold in rules:
        # RANGE windows use event-time, including candidates from every file and chunk.
        count = 'count(DISTINCT distinct_value)' if kind == 'distinct_threshold' else 'count(*)'
        db.execute(f'''CREATE OR REPLACE TEMP TABLE hits AS
            SELECT *, {count} OVER w AS hits, min(ts) OVER w AS beginning
            FROM candidates WHERE rule_id=?
            WINDOW w AS (PARTITION BY group_key ORDER BY ts RANGE BETWEEN {int(window)} PRECEDING AND CURRENT ROW)''', [rule_id])
        # Deterministic episodes: emit one aggregate per connected interval of threshold hits.
        db.execute('''CREATE OR REPLACE TEMP TABLE episodes AS
            WITH qualifying AS (SELECT *, lag(ts) OVER (PARTITION BY group_key ORDER BY ts,"offset",file) AS prev
                                FROM hits WHERE hits >= threshold),
            numbered AS (SELECT *, sum(CASE WHEN prev IS NULL OR ts-prev > "window" THEN 1 ELSE 0 END)
                                OVER (PARTITION BY group_key ORDER BY ts,"offset",file) AS episode FROM qualifying)
            SELECT group_key,episode,min(beginning) AS first_event,max(ts) AS last_event
            FROM numbered GROUP BY group_key,episode''')
        db.execute('''INSERT INTO alerts
            SELECT c.* REPLACE (e.first_event AS first_ts, e.last_event AS last_ts,
                     count(*) OVER (PARTITION BY c.group_key,e.episode) AS count)
            FROM candidates c JOIN episodes e ON c.group_key=e.group_key AND c.ts BETWEEN e.first_event AND e.last_event
            WHERE c.rule_id=?
            QUALIFY row_number() OVER (PARTITION BY c.group_key,e.episode ORDER BY c.ts,c.file,c.offset)=1''', [rule_id])
    db.execute('CREATE INDEX IF NOT EXISTS alerts_time ON alerts(ts)')
    db.execute('CREATE INDEX IF NOT EXISTS alerts_id ON alerts(alert_id)')


def _run(path, db_path=None, workers=None, progress=None, chunk_size=64*1024*1024, memory=None):
    started = time.monotonic()
    path = Path(path)
    if not path.exists(): raise ValueError('Log path does not exist')
    engine = RuleEngine()
    chunks = list(ranges(path, chunk_size))
    if not chunks: raise ValueError('No supported, nonempty text log files found')
    signature = hashlib.sha256(json.dumps(['scanner-v1',chunks,engine.fingerprint]).encode()).hexdigest()[:24]
    with connect(db_path) as db:
        dbfile = Path(db.execute('PRAGMA database_list').fetchone()[2])
        done = dict(db.execute('SELECT chunk_id,parquet FROM chunks WHERE run_id=?',[signature]).fetchall())
    outdir = dbfile.parent / 'partials' / signature
    outdir.mkdir(parents=True, exist_ok=True)
    total, processed, peak, outputs = sum(x[2]-x[1] for x in chunks), 0, 0, []
    tasks = []
    for c in chunks:
        cid = hashlib.sha256(json.dumps(c).encode()).hexdigest()[:24]
        output = str(outdir / (cid+'.parquet'))
        if cid in done and Path(done[cid]).exists():
            outputs.append(output); processed += c[2]-c[1]
        else: tasks.append((cid, (*c, output, str(engine.path))))
    configured = os.environ.get('WORKERS','auto')
    workers = workers or (int(configured) if configured != 'auto' else min(os.cpu_count() or 1,4))
    if not 1 <= workers <= 16: raise ValueError('Worker count must be between 1 and 16')
    context = multiprocessing.get_context('spawn')
    proc = psutil.Process()
    with concurrent.futures.ProcessPoolExecutor(max_workers=workers, mp_context=context) as pool:
        pending = {pool.submit(scan_range, task): cid for cid,task in tasks}
        while pending:
            ready, _ = concurrent.futures.wait(pending, timeout=0.5, return_when=concurrent.futures.FIRST_COMPLETED)
            rss = proc.memory_info().rss
            for child in proc.children(recursive=True):
                try: rss += child.memory_info().rss
                except psutil.Error: pass
            peak = max(peak, rss)
            for future in ready:
                cid = pending.pop(future); result = future.result()
                processed += result['bytes']; outputs.append(result['parquet'])
                with connect(db_path) as db:
                    db.execute('INSERT OR REPLACE INTO chunks VALUES (?,?,?)',[signature,cid,result['parquet']])
            seconds = time.monotonic()-started
            state = dict(running=True,percent=processed/total*100,mbps=processed/1e6/max(seconds,.001),eta=round((total-processed)/(processed/max(seconds,.001))) if processed else None,peak_gb=peak/1e9)
            if progress: progress(state)
    # Only publish a completed generation. Readers see the previous complete result during extraction.
    from backend.correlate import build
    with connect(db_path) as db:
        db.execute('BEGIN TRANSACTION')
        try:
            materialize(db, outputs)
            stats = dict(running=False,percent=100,mbps=total/1e6/max(time.monotonic()-started,.001),seconds=time.monotonic()-started,peak_gb=peak/1e9,bytes=total,files=len({c[0] for c in chunks}),run_id=signature)
            build(db, stats)
            stats['peak_gb'] = max(peak,memory[0] if memory else peak)/1e9
            stats['peak_scope'] = 'sampled parent and child RSS across extraction, aggregation and correlation; not a Docker measurement'
            stats['seconds'] = time.monotonic()-started
            stats['mbps'] = total/1e6/stats['seconds']
            try: stats['cgroup_peak_bytes'] = int(Path('/sys/fs/cgroup/memory.peak').read_text())
            except OSError: stats['cgroup_peak_bytes'] = None
            db.execute('INSERT OR REPLACE INTO cache VALUES (?,?)',['stats',json.dumps(stats)])
            db.execute('COMMIT')
        except BaseException:
            db.execute('ROLLBACK'); raise
    if progress: progress(stats)
    return stats


def run(path, db_path=None, workers=None, progress=None, chunk_size=64*1024*1024):
    stop=threading.Event();memory=[0];proc=psutil.Process()
    def monitor():
        while not stop.is_set():
            rss=proc.memory_info().rss
            for child in proc.children(recursive=True):
                try: rss+=child.memory_info().rss
                except psutil.Error: pass
            memory[0]=max(memory[0],rss)
            stop.wait(.1)
    thread=threading.Thread(target=monitor,daemon=True);thread.start()
    try: return _run(path,db_path,workers,progress,chunk_size,memory)
    finally: stop.set();thread.join()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--path', default=os.environ.get('LOG_PATH','/data'))
    parser.add_argument('--workers', type=int)
    parser.add_argument('--benchmark', help='Generate repeated sample to this size, e.g. 50GB. Accuracy is meaningless.')
    args = parser.parse_args()
    if not args.benchmark:
        # When exec'd in the running backend, delegate to its sole DuckDB owner.
        import requests
        url=os.environ.get('SCAN_API_URL','http://127.0.0.1:8000')
        headers={'Authorization':'Bearer '+os.environ['API_TOKEN']} if os.environ.get('API_TOKEN') else {}
        try:
            available=requests.get(url+'/health',timeout=2).ok
        except requests.RequestException: available=False
        if available:
            response=requests.post(url+'/scan',json={'path':args.path},headers=headers,timeout=10)
            response.raise_for_status()
            while True:
                response=requests.get(url+'/scan/status',headers=headers,timeout=30);response.raise_for_status();state=response.json()
                print(json.dumps(state),flush=True)
                if not state['running']:
                    if state.get('error'): raise RuntimeError(state['error'])
                    return
                time.sleep(2)
    if args.benchmark:
        import re
        m = re.fullmatch(r'(\d+)(MB|GB)', args.benchmark)
        if not m: parser.error('Use e.g. 50GB')
        target = int(m[1]) * (10**9 if m[2]=='GB' else 10**6)
        source = next(iter(ranges(Path(args.path))), None)
        if not source: parser.error('No source sample')
        from backend.store import DB_PATH
        dest = Path(DB_PATH).parent / 'benchmark.log'
        remaining = target
        with open(dest,'wb') as output, open(source[0],'rb') as sample:
            while remaining:
                block = sample.read(min(1024*1024, remaining))
                if not block: sample.seek(0); continue
                output.write(block); remaining -= len(block)
            output.write(b'\n')
        args.path = str(dest)
        print('SYNTHETIC REPEATED INPUT: no accuracy claims apply.', flush=True)
    print(json.dumps(run(args.path, workers=args.workers, progress=lambda s: print(json.dumps(s),flush=True)),indent=2))


if __name__ == '__main__': main()
