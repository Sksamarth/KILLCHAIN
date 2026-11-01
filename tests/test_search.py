import json

from fastapi.testclient import TestClient

from backend.api import app
from backend.store import connect


def test_search_id_name_ip_account_host_and_status(tmp_path,monkeypatch):
    monkeypatch.setattr('backend.store.DB_PATH',str(tmp_path/'search.duckdb'))
    monkeypatch.delenv('API_TOKEN',raising=False)
    with connect() as db:
        db.execute('CREATE TABLE alerts (alert_id VARCHAR,host VARCHAR,new_user VARCHAR)')
        db.execute('CREATE TABLE incident_alerts (incident_id VARCHAR,alert_id VARCHAR)')
        db.execute("INSERT INTO alerts VALUES ('a','HR-07','new-admin')")
        db.execute("INSERT INTO incident_alerts VALUES ('123456','a')")
        for iid,status in [('123456','active'),('987654','suppressed')]:
            value=dict(id=iid,status=status,name='Password guessing',ips=['198.51.100.7'],users=['Alice'])
            db.execute('INSERT INTO incident_paths VALUES (?,?,?,?)',[iid,status,50,json.dumps(value)])
    with TestClient(app) as client:
        assert client.get('/health').json()['authentication_required'] is False
        for query in ['123456','#123456',' 123456 ','guessing','198.51.100.7','198.51.100','ALICE','hr-07','new-admin']:
            result=client.get('/incidents',params={'search':query})
            assert result.status_code==200
            assert [i['id'] for i in result.json()]==['123456'],query
        for query in ['missing',"' OR 1=1 --",'%']:
            assert client.get('/incidents',params={'search':query}).json()==[]
        assert client.get('/incidents',params={'status':'suppressed'}).json()[0]['id']=='987654'
        monkeypatch.setenv('API_TOKEN','example-test-key')
        assert client.get('/health').json()['authentication_required'] is True
        assert client.get('/incidents').status_code==401


def test_search_before_any_scan(tmp_path,monkeypatch):
    monkeypatch.setattr('backend.store.DB_PATH',str(tmp_path/'empty.duckdb'))
    monkeypatch.delenv('API_TOKEN',raising=False)
    with TestClient(app) as client:
        assert client.get('/incidents',params={'search':'anything'}).json()==[]
