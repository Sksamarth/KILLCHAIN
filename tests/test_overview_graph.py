import json

from fastapi.testclient import TestClient

from backend.api import app
from backend.scanner import materialize,ranges,scan_range
from backend.correlate import build
from backend.rules import ROOT
from backend.store import connect


def setup_data(tmp_path,monkeypatch,hostless=False):
    monkeypatch.setattr('backend.store.DB_PATH',str(tmp_path/'overview.duckdb'))
    monkeypatch.delenv('API_TOKEN',raising=False)
    source=tmp_path/'signals.jsonl'
    rows=[dict(timestamp=1792745306+i,host=host,user=user,event_type='flow',src_ip=src,dst_ip=dst,dst_port=443,bytes=150000000,status='success')
        for i,(host,user,src,dst) in enumerate([('HR-07','alice','10.0.0.7','198.51.100.1'),('FS-02','bob','10.0.0.2','198.51.100.2')])]
    if hostless:
        for row in rows:row['host']=''
    source.write_text(''.join(json.dumps(r)+'\n' for r in rows),encoding='utf8')
    out=str(tmp_path/'signals.parquet');scan_range((*next(ranges(source)),out,str(ROOT/'rules/detect.yaml')))
    with connect() as db:materialize(db,[out]);build(db,{})


def test_overview_uses_all_incidents_and_typed_entities(tmp_path,monkeypatch):
    setup_data(tmp_path,monkeypatch)
    with TestClient(app) as client:
        result=client.get('/overview/graph').json()
        assert result['totals']['hosts']==2 and result['totals']['detections']==2
        assert result['totals']['accounts']==2 and result['totals']['assets']==4
        assert result['totals']['incidents']==2
        assert {n['id'] for n in result['nodes']}>={'host:HR-07','account:alice','ip:10.0.0.7'}
        assert len(result['edges'])==6 and not result['limited']
        assert result['remaining_assets'] is None and result['confirmed_exploits'] is None
        assert client.get('/overview/graph?stage=0').json()['totals']['detections']==0
        assert client.get('/overview/graph?status=suppressed').json()['totals']['detections']==0


def test_click_details_are_scoped_and_keep_source_evidence(tmp_path,monkeypatch):
    setup_data(tmp_path,monkeypatch)
    with TestClient(app) as client:
        detail=client.get('/overview/graph/details',params={'node':'host:HR-07'}).json()
        assert detail['metrics']['detections']==detail['metrics']['hosts']==1
        assert detail['metrics']['assets']==2
        assert detail['techniques'][0]['technique']=='T1041'
        assert detail['evidence'][0]['host']=='HR-07' and detail['evidence'][0]['offset']==0
        assert len(detail['incidents'])==1 and detail['remaining_assets'] is None
        edge=client.get('/overview/graph/details',params={'source':'account:alice','target':'host:HR-07','relation':'account'}).json()
        assert edge['metrics']['detections']==1 and edge['evidence']==detail['evidence']
        assert client.get('/overview/graph/details',params={'node':"' OR true --"}).json()['metrics']['detections']==0
        assert client.get('/overview/graph/details?source=x').status_code==422
        assert client.get('/overview/graph/details?node=x&source=y&target=z&relation=account').status_code==422


def test_empty_graph_before_scan_and_authentication(tmp_path,monkeypatch):
    monkeypatch.setattr('backend.store.DB_PATH',str(tmp_path/'empty.duckdb'))
    monkeypatch.delenv('API_TOKEN',raising=False)
    with TestClient(app) as client:
        assert client.get('/overview/graph').json()['nodes']==[]
        assert client.get('/overview/graph/details?node=host:x').json()['evidence']==[]
        monkeypatch.setenv('API_TOKEN','example-key')
        assert client.get('/overview/graph').status_code==401


def test_hostless_network_logs_keep_account_links_and_internal_asset_identities(tmp_path,monkeypatch):
    setup_data(tmp_path,monkeypatch,hostless=True)
    with TestClient(app) as client:
        result=client.get('/overview/graph').json()
        assert result['totals']['hosts']==0 and result['totals']['assets']==2
        assert result['totals']['accounts']==2
        assert any(n['id']=='ip:10.0.0.7' and n['kind']=='host' and n['identity_type']=='ip' for n in result['nodes'])
        edge=next(e for e in result['edges'] if e['source']=='account:alice')
        assert edge['target']=='ip:198.51.100.1' and edge['relation']=='account'
        detail=client.get('/overview/graph/details',params={k:edge[k] for k in ('source','target','relation')}).json()
        assert detail['metrics']['detections']==1 and detail['metrics']['assets']==1
