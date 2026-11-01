import json
import logging
import os
import threading
import time
from contextlib import asynccontextmanager
from pathlib import Path, PureWindowsPath

from fastapi import FastAPI, HTTPException, Query, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from backend.rules import ROOT, RuleEngine
from backend.store import LOCK, connect, records

@asynccontextmanager
async def lifespan(app):
    RuleEngine()
    with connect() as db: db.execute('SELECT 1')
    yield


app = FastAPI(title='KillChain XDR', version='0.1.0',lifespan=lifespan)
app.add_middleware(CORSMiddleware,allow_origins=os.environ.get('CORS_ORIGINS','http://localhost:8080').split(','),allow_methods=['GET','POST'],allow_headers=['Content-Type','Authorization'])
state = {'running': False, 'percent': 0}
job_lock = threading.Lock()


@app.middleware('http')
async def access_control(request: Request, call_next):
    token = os.environ.get('API_TOKEN')
    if token and request.url.path != '/health' and request.headers.get('authorization') != 'Bearer '+token:
        return Response(content='{"detail":"Authentication required"}',status_code=401,media_type='application/json')
    started = time.perf_counter()
    response = await call_next(request)
    response.headers['X-Latency-Ms'] = f'{(time.perf_counter()-started)*1000:.2f}'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response


def cached(key, fallback):
    with connect() as db:
        row = db.execute('SELECT value FROM cache WHERE key=?',[key]).fetchone()
    return json.loads(row[0]) if row else fallback


@app.get('/health')
def health():
    RuleEngine()
    # A publishing scan owns this lock for minutes. It must not make the
    # liveness probe queue behind that transaction and time out.
    if not LOCK.acquire(blocking=False):
        return {'status':'ok','service':'killchain-xdr','database':'busy','authentication_required':bool(os.environ.get('API_TOKEN'))}
    try:
        with connect() as db: db.execute('SELECT 1')
        return {'status':'ok','service':'killchain-xdr','database':'ready','authentication_required':bool(os.environ.get('API_TOKEN'))}
    finally:
        LOCK.release()


@app.get('/overview')
def overview():
    value = cached('overview',dict(totals={k:0 for k in ['incidents','incidents_critical','alerts','alerts_critical','assets','assets_risky','users','users_risky','suppressed']},stages=[{'critical':0,'total':0} for _ in range(5)],tactics=[],incidents=[],assets=[],scan={}))
    value['scan'] = stats()
    return value


@app.get('/stats')
def stats():
    value=cached('stats',{})
    if value.get('cold_run') is False and value.get('mbps') is not None:
        value['resumed_mbps']=value['mbps'];value['mbps']=None
    return value


@app.get('/incidents')
def incidents(status: str = Query('active',pattern='^(active|suppressed|all)$'),offset: int = Query(0,ge=0),limit: int = Query(50,ge=1,le=500),search: str=Query('',max_length=200)):
    search=search.strip()
    if search.startswith('#') and search[1:].isdigit(): search=search[1:]
    with connect() as db:
        where = 'WHERE true' if status=='all' else 'WHERE status=?'
        args = [] if status=='all' else [status]
        if search:
            # Extract small searchable summaries once. Applying multiple JSON
            # functions to large graph documents can exceed the query budget.
            if not db.execute("SELECT count(*) FROM information_schema.tables WHERE table_name='incident_search'").fetchone()[0]:
                summaries=[]
                cursor=db.execute('SELECT incident_id,path_json FROM incident_paths')
                while row:=cursor.fetchone():
                    value=json.loads(row[1])
                    text=' '.join([row[0],value.get('name',''),*value.get('ips',[]),*value.get('users',[])])
                    summaries.append((row[0],text))
                db.execute('CREATE TABLE incident_search (incident_id VARCHAR, search_text VARCHAR)')
                if summaries: db.executemany('INSERT INTO incident_search VALUES (?,?)',summaries)
            clauses=['incident_id IN (SELECT incident_id FROM incident_search WHERE contains(lower(search_text),lower(?)))']
            args += [search]
            if db.execute("SELECT count(*) FROM information_schema.tables WHERE table_name IN ('alerts','incident_alerts')").fetchone()[0]==2:
                clauses.append('''incident_id IN (SELECT m.incident_id FROM incident_alerts m JOIN alerts a USING(alert_id)
                    WHERE
                    (contains(lower(a.host),lower(?)) OR contains(lower(a.new_user),lower(?))))''')
                args += [search,search]
            where += ' AND ('+' OR '.join(clauses)+')'
        rows=db.execute(f'SELECT path_json FROM incident_paths {where} ORDER BY risk DESC,incident_id LIMIT ? OFFSET ?',args+[limit,offset]).fetchall()
    return [{k:v for k,v in json.loads(row[0]).items() if k not in {'nodes','edges','timeline','next_hops','report'}} for row in rows]


@app.get('/incidents/{incident_id}/path')
def incident_path(incident_id: str):
    with connect() as db:
        row=db.execute('SELECT path_json FROM incident_paths WHERE incident_id=?',[incident_id]).fetchone()
        if not row: raise HTTPException(404,'Incident not found')
        value=json.loads(row[0])
        if value.pop('lazy_path',False):
            from backend.graph import path_for
            import yaml
            evidence=records(db.execute('SELECT a.* FROM alerts a JOIN incident_alerts i USING(alert_id) WHERE incident_id=? ORDER BY ts,a.file,a."offset",a.rule_id',[incident_id]))
            access=records(db.execute('SELECT * FROM access_history'))
            snapshot=db.execute("SELECT value FROM cache WHERE key='report_templates'").fetchone()
            templates=json.loads(snapshot[0]) if snapshot else yaml.safe_load((ROOT/'rules/report.yaml').read_text())['templates']
            value.update(path_for(evidence,access,templates))
        return value


@app.get('/incidents/{incident_id}/report')
def report(incident_id: str): return {'report':incident_path(incident_id)['report']}


@app.get('/ai/status')
def ai_status():
    from backend.ai_review import status
    return status()


@app.post('/incidents/{incident_id}/ai-review')
def ai_review(incident_id: str):
    from backend.ai_review import review,ReviewError
    try:return review(incident_path(incident_id))
    except ReviewError as exc:raise HTTPException(exc.status,exc.message) from None


@app.get('/incidents/{incident_id}/alerts')
def alerts(incident_id: str,offset: int=Query(0,ge=0),limit: int=Query(100,ge=1,le=1000)):
    incident_path(incident_id)
    with connect() as db:
        return records(db.execute('SELECT a.* FROM alerts a JOIN incident_alerts i USING(alert_id) WHERE incident_id=? ORDER BY ts LIMIT ? OFFSET ?',[incident_id,limit,offset]))


class ScanRequest(BaseModel):
    path: str = Field(default='/data',min_length=1,max_length=2048)
    workers: int | None = Field(default=None,ge=1,le=16)


def allowed_path(value):
    root = Path(os.environ.get('LOG_PATH','/data')).resolve()
    value = value.strip().strip('"').strip("'")
    host_root = os.environ.get('HOST_LOG_PATH','')
    windows_path = PureWindowsPath(value)
    native_path = Path(value).resolve()
    if native_path.is_relative_to(root):
        path = native_path
    elif host_root and windows_path.is_absolute() and PureWindowsPath(host_root).is_absolute():
        try:
            relative = windows_path.relative_to(PureWindowsPath(host_root))
        except ValueError:
            raise HTTPException(400,'Windows path must be inside the mounted data folder; use /data for the Docker path')
        path = root.joinpath(*relative.parts).resolve()
    else:
        path = Path(value).resolve()
    if not path.is_relative_to(root): raise HTTPException(400,'Path must be inside the configured log mount')
    if not path.exists(): raise HTTPException(400,'Log path does not exist')
    return path


@app.post('/scan',status_code=202)
def scan(body: ScanRequest):
    path = allowed_path(body.path)
    if not job_lock.acquire(blocking=False): raise HTTPException(409,'A scan is already running')
    state.clear(); state.update(running=True,percent=0,phase='extracting',path=str(path))
    def work():
        from backend.scanner import run
        try: run(path,workers=body.workers,progress=lambda s:state.update(s))
        except Exception as exc:
            logging.exception('Scan failed')
            detail=str(exc)[:350] if isinstance(exc,(ValueError,OSError)) else type(exc).__name__+'. See backend logs for details.'
            state.update(running=False,error='Scan failed: '+detail)
        finally: job_lock.release()
    threading.Thread(target=work,daemon=True).start()
    return {'status':'accepted'}


@app.get('/scan/status')
def scan_status(): return dict(state)


@app.get('/evidence')
def evidence(file: str=Query(min_length=1,max_length=2048),offset: int=Query(ge=0)):
    with connect() as db:
        if not db.execute("SELECT count(*) FROM information_schema.tables WHERE table_name='alert_evidence'").fetchone()[0]: return []
        rows=records(db.execute('''SELECT e.*,i.incident_id FROM alert_evidence e
            JOIN incident_alerts i USING(alert_id) JOIN incident_paths p USING(incident_id)
            WHERE e."offset"=? AND p.status='active' ''',[offset]))
    def normal(value): return value.replace('\\','/')
    return [r for r in rows if normal(r['file'])==normal(file) or normal(r['file']).endswith('/'+normal(file))]


if (ROOT/'frontend').exists(): app.mount('/ui',StaticFiles(directory=ROOT/'frontend',html=True),name='ui')
