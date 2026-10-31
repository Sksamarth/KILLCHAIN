import json
import logging
import os
import threading
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from backend.rules import ROOT, RuleEngine
from backend.store import connect, records

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
    with connect() as db: db.execute('SELECT 1')
    return {'status':'ok'}


@app.get('/overview')
def overview():
    value = cached('overview',dict(totals={k:0 for k in ['incidents','incidents_critical','alerts','alerts_critical','assets','assets_risky','users','users_risky','suppressed']},stages=[{'critical':0,'total':0} for _ in range(5)],tactics=[],incidents=[],assets=[],scan={}))
    value['scan'] = cached('stats',{})
    return value


@app.get('/stats')
def stats(): return cached('stats',{})


@app.get('/incidents')
def incidents(status: str = Query('active',pattern='^(active|suppressed|all)$'),offset: int = Query(0,ge=0),limit: int = Query(50,ge=1,le=500)):
    with connect() as db:
        where = '' if status=='all' else 'WHERE status=?'
        args = [] if status=='all' else [status]
        rows=db.execute(f'SELECT path_json FROM incident_paths {where} ORDER BY risk DESC,incident_id LIMIT ? OFFSET ?',args+[limit,offset]).fetchall()
    return [{k:v for k,v in json.loads(row[0]).items() if k not in {'nodes','edges','timeline','next_hops','report'}} for row in rows]


@app.get('/incidents/{incident_id}/path')
def incident_path(incident_id: str):
    with connect() as db: row=db.execute('SELECT path_json FROM incident_paths WHERE incident_id=?',[incident_id]).fetchone()
    if not row: raise HTTPException(404,'Incident not found')
    return json.loads(row[0])


@app.get('/incidents/{incident_id}/report')
def report(incident_id: str): return {'report':incident_path(incident_id)['report']}


@app.get('/incidents/{incident_id}/alerts')
def alerts(incident_id: str,offset: int=Query(0,ge=0),limit: int=Query(100,ge=1,le=1000)):
    incident_path(incident_id)
    with connect() as db:
        return records(db.execute('SELECT a.* FROM alerts a JOIN incident_alerts i USING(alert_id) WHERE incident_id=? ORDER BY ts LIMIT ? OFFSET ?',[incident_id,limit,offset]))


class ScanRequest(BaseModel):
    path: str = Field(default='/data',min_length=1,max_length=2048)


def allowed_path(value):
    root = Path(os.environ.get('LOG_PATH','/data')).resolve()
    path = Path(value).resolve()
    if not path.is_relative_to(root): raise HTTPException(400,'Path must be inside the configured log mount')
    if not path.exists(): raise HTTPException(400,'Log path does not exist')
    return path


@app.post('/scan',status_code=202)
def scan(body: ScanRequest):
    path = allowed_path(body.path)
    if not job_lock.acquire(blocking=False): raise HTTPException(409,'A scan is already running')
    state.clear(); state.update(running=True,percent=0,phase='extracting')
    def work():
        from backend.scanner import run
        try: run(path,progress=lambda s:state.update(s))
        except Exception:
            logging.exception('Scan failed')
            state.update(running=False,error='Scan failed. See backend logs for details.')
        finally: job_lock.release()
    threading.Thread(target=work,daemon=True).start()
    return {'status':'accepted'}


@app.get('/scan/status')
def scan_status(): return dict(state)


if (ROOT/'frontend').exists(): app.mount('/ui',StaticFiles(directory=ROOT/'frontend',html=True),name='ui')
