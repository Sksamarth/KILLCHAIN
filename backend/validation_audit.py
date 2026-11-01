"""Validate the evaluator through an isolated real HTTP API, never live data."""
import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time

import requests

from backend.validation import validate


def audit(output,seed=701,background=80):
    folder=Path(output).resolve();folder.mkdir(parents=True,exist_ok=True)
    direct=validate(folder,seed=seed,background=background)
    env=os.environ.copy();env['DB_PATH']=str(folder/'validation.duckdb')
    env['API_TOKEN']='';env['GEMINI_API_KEY']=''
    with socket.socket() as sock:
        sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
    base=f'http://127.0.0.1:{port}'
    flags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0
    with (folder/'audit-api.log').open('w',encoding='utf8') as log:
        server=subprocess.Popen([sys.executable,'-m','uvicorn','backend.api:app','--host','127.0.0.1','--port',str(port)],
            env=env,stdout=log,stderr=subprocess.STDOUT,creationflags=flags)
        try:
            deadline=time.monotonic()+20
            while time.monotonic()<deadline:
                if server.poll() is not None:raise RuntimeError('Isolated validation API exited; inspect audit-api.log')
                try:
                    if requests.get(base+'/health',timeout=1).status_code==200:break
                except requests.RequestException:pass
                time.sleep(.1)
            else:raise RuntimeError('Isolated validation API did not become ready')
            evaluated=subprocess.run([sys.executable,'-m','backend.evaluate','--truth',str(folder/'truth.json'),'--url',base],
                env=env,capture_output=True,text=True,timeout=120,creationflags=flags)
            if not evaluated.stdout.strip():raise RuntimeError('HTTP evaluator returned no report; '+evaluated.stderr[-400:])
            http=json.loads(evaluated.stdout)
        finally:
            server.terminate()
            try:server.wait(timeout=10)
            except subprocess.TimeoutExpired:server.kill();server.wait(timeout=10)
    keys=('detection','labels','parent_labels','stages','stage_coverage','attack_paths','false_alarms',
          'merged_incidents','exact_membership_checked','known_benign_incidents','unmatched_detections')
    comparisons={key:dict(direct=direct[key],http=http[key],matches=direct[key]==http[key]) for key in keys}
    result=dict(engine_checks_passed=all(item['matches'] for item in comparisons.values()) and evaluated.returncode==1 and http['great_gate']!='PASS',
        scope='Small synthetic fixture in an isolated database and temporary localhost API. Live dashboard data unchanged; not real-data accuracy or scale certification.',
        seed=seed,background_records=background,comparisons=comparisons,http_exit_code=evaluated.returncode,
        scenario_accuracy_gate=direct['accuracy_gate'],release_gate=http['great_gate'],accuracy_scope=http['accuracy_scope'],
        source_sha256=direct['source_sha256'],http_p95_ms=http['p95_ms'],
        benign_failures=direct['benign_failures'])
    (folder/'http-evaluation.json').write_text(json.dumps(http,indent=2),encoding='utf8')
    (folder/'engine-audit.json').write_text(json.dumps(result,indent=2),encoding='utf8')
    return result


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--output',default='tmp/validation-engine-audit');parser.add_argument('--seed',type=int,default=701);parser.add_argument('--background',type=int,default=80)
    args=parser.parse_args();result=audit(args.output,args.seed,args.background)
    print(json.dumps(result,indent=2));return 0 if result['engine_checks_passed'] else 1


if __name__=='__main__':raise SystemExit(main())
