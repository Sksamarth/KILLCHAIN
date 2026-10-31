import copy
import json
from pathlib import Path

import pytest
import yaml

from backend.correlate import components, sequences
from backend.evaluate import score
from backend.graph import path_for
from backend.rules import ROOT, RuleEngine, condition, private
from backend.scanner import materialize, ranges, scan_range
from backend.store import connect, records


def login(n,success=False,user='admin',src='198.51.100.7'):
    return (f'eventtime={(1792745306+n)*1000000000} type="event" subtype="system" logdesc="Admin login {"successful" if success else "failed"}" user="{user}" ui="https(x)" method="https" srcip={src} srcintf="wan1" srcintfrole="wan" dstip=10.10.99.1 reason="passwd_invalid"\n').encode()


@pytest.mark.parametrize('ip,expected',[('10.1.2.3',True),('172.16.1.1',True),('172.32.1.1',False),('198.51.100.1',False),('203.0.113.1',False),('127.0.0.1',True),('169.254.1.1',True),('::1',True),('invalid',False)])
def test_private(ip,expected): assert private(ip)==expected


def test_conditions():
    assert condition('100','>99') and not condition('bad','>99')
    assert condition('high','in:high,critical') and condition('Phishing','contains:Phish')
    with pytest.raises(ValueError): condition('x','unsafe')


@pytest.mark.parametrize('change',[{'technique':'T9999'},{'tactic':'Unknown'},{'match':'['},{'where':{'missing':'eq:a'}}])
def test_invalid_yaml(tmp_path,change):
    config=yaml.safe_load((ROOT/'rules/detect.yaml').read_text());config['rules'][0].update(change)
    p=tmp_path/'detect.yaml';p.write_text(yaml.safe_dump(config))
    (tmp_path/'sequence.yaml').write_text('sequences: []')
    with pytest.raises((ValueError,Exception)): RuleEngine(p)


def test_cross_chunk_and_file_thresholds(tmp_path):
    # No overlap is needed: global aggregation must recover windows across both boundaries.
    folder=tmp_path/'input';folder.mkdir()
    (folder/'a.log').write_bytes(b''.join(login(n) for n in range(11)))
    (folder/'b.log').write_bytes(b''.join(login(n) for n in range(11,23))+login(25,True))
    outputs=[]
    for i,task in enumerate(ranges(folder,500)):
        out=str(tmp_path/f'{i}.parquet');scan_range((*task,out,str(ROOT/'rules/detect.yaml')));outputs.append(out)
    with connect(tmp_path/'test.duckdb') as db:
        materialize(db,outputs)
        alerts=records(db.execute('SELECT * FROM alerts ORDER BY ts'))
    brute=[a for a in alerts if a['rule_id']=='R001']
    assert len(brute)==1 and brute[0]['count']==23
    assert len([a for a in alerts if a['rule_id']=='R010'])==1
    assert brute[0]['first_ts']==1792745306 and brute[0]['last_ts']==1792745328


def test_distinct_threshold_and_expiry(tmp_path):
    f=tmp_path/'spray.log'
    f.write_bytes(b''.join(login(n,user=f'u{n}',src=f'45.74.28.{n+1}') for n in range(10)))
    out=str(tmp_path/'out.parquet');scan_range((*next(ranges(f)),out,str(ROOT/'rules/detect.yaml')))
    with connect(tmp_path/'test.duckdb') as db:
        materialize(db,[out]); rows=records(db.execute('SELECT * FROM alerts'))
    assert len(rows)==1 and rows[0]['rule_id']=='R002' and rows[0]['count']==10
    f.write_bytes(b''.join(login(n*400,user=f'u{n}',src=f'45.74.28.{n+1}') for n in range(10)))
    scan_range((*next(ranges(f)),out,str(ROOT/'rules/detect.yaml')))
    with connect(tmp_path/'test2.duckdb') as db:
        materialize(db,[out]); assert db.execute('SELECT count(*) FROM alerts').fetchone()[0]==0


def alert(n,src,dst,rule='R010',user=''):
    a=next(RuleEngine().candidates(login(n,True,user=user,src=src),'test.log',n))
    a.update(dst_ip=dst,rule_id=rule);return a


def test_hub_and_time_separation():
    config=dict(stoplist=[],entity_degree_cap=2,max_gap_seconds=60)
    rows=[alert(i,f'198.51.100.{i+1}','10.10.99.1') for i in range(4)]
    assert len(components(rows,config))==4
    rows=[alert(0,'198.51.100.1','10.1.1.1'),alert(1000,'198.51.100.1','10.1.1.1')]
    assert len(components(rows,config))==2


def test_ordered_sequence_report_and_evidence():
    a=alert(0,'198.51.100.1','10.1.1.1',rule='R001',user='admin');b=alert(10,'198.51.100.1','10.1.1.1',user='admin')
    spec=[dict(id='test',steps=['R001','R010'],same=['user','src_ip'],within=60,bonus_score=20)]
    assert sequences([b,a],spec)==(['test'],20)
    b['ts']=a['ts']-100
    assert sequences([b,a],spec)==([],0)
    templates={'default':'{rule_name}: {src_ip} to {dst_ip}.'}
    p=path_for([a],[],templates)
    assert p['next_hops']==[] and '198.51.100.1' in p['report'] and p['timeline'][0]['offset']==0


def test_evaluation_requires_same_incident_and_order():
    truth={'attacks':[{'id':'a','steps':[{'file':'a.log','offset':1,'technique':'T1078'},{'file':'a.log','offset':2,'technique':'T1041'}]}]}
    paths=[dict(id='1',timeline=[dict(file='a.log',offset=1,tech='T1078'),dict(file='a.log',offset=2,tech='T1041')])]
    assert score(paths,truth)['attack_paths']==1
    paths[0]['timeline'].reverse()
    assert score(paths,truth)['attack_paths']==0


def test_api_paths_and_pagination(tmp_path,monkeypatch):
    import backend.store as store
    monkeypatch.setattr(store,'DB_PATH',str(tmp_path/'api.duckdb'))
    from backend.api import app
    from fastapi.testclient import TestClient
    with TestClient(app) as client:
        assert client.get('/health').status_code==200
        assert client.get('/overview').json()['totals']['incidents']==0
        assert client.get('/incidents?limit=0').status_code==422
        assert client.get('/incidents/missing/path').status_code==404
        assert client.post('/scan',json={'path':'/etc'}).status_code==400
        monkeypatch.setenv('API_TOKEN','test-secret')
        assert client.get('/overview').status_code==401
        assert client.get('/overview',headers={'Authorization':'Bearer test-secret'}).status_code==200
