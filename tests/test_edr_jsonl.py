import json

import pytest

from backend.rules import ROOT, RuleEngine
from backend.scanner import ranges, scan_range


def record(action,technique,kind='alert',**extra):
    value={'@timestamp':'2026-11-01T01:06:59.631585+00:00',
           'event':{'kind':kind,'action':action,'category':['intrusion_detection']},
           'host':{'name':'WS-FIN-011','ip':['10.10.1.222']},'user':{'name':'alice'},
           'threat':{'technique':{'id':[technique]}},
           'labels':{'synthetic':'true','simulated_detection':'true'}}
    value.update(extra)
    return (json.dumps(value)+'\n').encode()


@pytest.mark.parametrize('action,technique,rule',[
    ('suspicious_process_execution','T1059.001','R200'),
    ('suspicious_network_connection','T1071.001','R201'),
    ('multiple_failed_logins','T1110','R202'),
    ('registry_persistence','T1547.001','R203'),
    ('mass_file_rename','T1486','R204'),
])
def test_reported_edr_alerts(action,technique,rule):
    alerts=list(RuleEngine().candidates(record(action,technique),'edr.jsonl',100))
    assert [a['rule_id'] for a in alerts]==[rule]
    assert alerts[0]['technique']==technique and alerts[0]['host']=='WS-FIN-011'
    assert alerts[0]['count']==1 and alerts[0]['offset']==100
    assert 'provider annotation' in alerts[0]['rule_name']


def test_annotations_do_not_replace_raw_detection_requirements():
    engine=RuleEngine()
    assert not list(engine.candidates(record('registry_persistence','T1547.001',kind='event'),'edr.jsonl',0))
    assert not list(engine.candidates(record('registry_persistence','T9999'),'edr.jsonl',0))
    assert not list(engine.candidates(record('registry_persistence','T1486'),'edr.jsonl',0))
    raw=record('multiple_failed_logins','T1110',winlog={'event_id':4625,'failed_count_5min':100},source={'ip':'198.51.100.1'})
    alerts=list(engine.candidates(raw,'edr.jsonl',0))
    assert [a['rule_id'] for a in alerts]==['R202'] and alerts[0]['count']==1


def test_edr_ingestion_counts_known_telemetry_and_simulated_reports(tmp_path):
    file=tmp_path/'edr.jsonl'
    file.write_bytes(record('mass_file_rename','T1486')+
                     record('registry_persistence','T9999')+
                     record('process_created','T1547.001',kind='event'))
    result=scan_range((*next(ranges(file)),str(tmp_path/'out.parquet'),str(ROOT/'rules/detect.yaml')))
    assert result['lines']==3 and result['unsupported_lines']==0
    assert result['synthetic_lines']==3 and result['reported_alert_lines']==2 and result['unmapped_report_lines']==1
