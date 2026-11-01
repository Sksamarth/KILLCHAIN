import copy
import json
import sys

import pytest

from backend.evaluate import main,release_gate,score,validate_truth


def fixture():
    truth=dict(exhaustive_steps=True,attacks=[dict(id='a',steps=[
        dict(file='auth.log',offset=1,technique='T1110.001',stage=0),
        dict(file='auth.log',offset=2,technique='T1078',stage=0)])])
    paths=[dict(id='1',timeline=[dict(file='/data/auth.log',offset=s['offset'],tech=s['technique'],stage=s['stage'],alert_id=str(i)) for i,s in enumerate(truth['attacks'][0]['steps'])])]
    return paths,truth


@pytest.mark.parametrize('fault',['missing','technique','stage','order','split','extra','benign'])
def test_corrupted_results_cannot_pass_path_validation(fault):
    paths,truth=fixture()
    if fault=='missing':paths[0]['timeline'].pop()
    elif fault=='technique':paths[0]['timeline'][0]['tech']='T1110'
    elif fault=='stage':paths[0]['timeline'][0]['stage']=3
    elif fault=='order':paths[0]['timeline'].reverse()
    elif fault=='split':paths.append(dict(id='2',timeline=[paths[0]['timeline'].pop()]))
    else:
        paths[0]['timeline'].append(dict(file='/data/auth.log',offset=99,tech='T1041',stage=4,alert_id='extra'))
        if fault=='benign':
            truth['exhaustive_steps']=False
            truth['benign']=[dict(file='auth.log',offset=99)]
    result=score(paths,truth)
    assert result['attack_paths']==0
    if fault=='missing':assert result['detection']==.5
    elif fault=='technique':assert result['labels']==.5 and result['parent_labels']==1
    elif fault=='stage':assert result['stages']==.5 and result['labels']==1
    elif fault=='benign':assert result['known_benign_incidents']==1
    elif fault=='extra':assert result['unmatched_detections']==1


def test_positive_control_and_false_alarm_denominator():
    paths,truth=fixture();result=score(paths,truth)
    assert result['detection']==result['labels']==result['stages']==result['attack_paths']==1
    assert result['false_alarms']==0 and result['exact_membership_checked']
    paths.append(dict(id='false',timeline=[dict(file='/data/auth.log',offset=88,tech='T1041',stage=4)]))
    result=score(paths,truth)
    assert result['attack_paths']==1 and result['false_alarms']==.5


def test_duplicate_detection_is_an_extra_step_under_exhaustive_truth():
    paths,truth=fixture()
    duplicate=copy.deepcopy(paths[0]['timeline'][0]);duplicate['alert_id']='duplicate'
    paths[0]['timeline'].insert(1,duplicate)
    result=score(paths,truth)
    assert result['unmatched_detections']==1 and result['attack_paths']==0


def test_no_detections_cannot_be_reported_as_perfect_or_pass_release():
    paths,truth=fixture();result=score([],truth)
    assert result['detection']==result['attack_paths']==0
    assert result['labels'] is None and result['false_alarms'] is None
    measured=gate_fixture();measured.update(result)
    assert release_gate(measured,truth)!='PASS'


def test_missing_expected_stages_are_unmeasured_not_implicitly_correct():
    paths,truth=fixture()
    for step in truth['attacks'][0]['steps']:step.pop('stage')
    result=score(paths,truth)
    assert result['stages'] is None and result['stage_coverage']==0
    measured=gate_fixture();measured.update(result)
    # Stage accuracy is an FR-3 check, not an extra threshold in the seven-metric rubric.
    assert release_gate(measured,truth)=='PASS'


def test_aggregate_evidence_can_reference_a_contributor_in_another_file():
    paths,truth=fixture()
    step=truth['attacks'][0]['steps'][0];step.update(file='second.log',offset=55)
    evidence={('second.log',55):[dict(file='/data/second.log',offset=55,alert_id='0')],
              ('auth.log',2):[dict(file='/data/auth.log',offset=2,alert_id='1')]}
    assert score(paths,truth,evidence)['attack_paths']==1
    evidence[('second.log',55)]=[]
    assert score(paths,truth,evidence)['detection']==.5


def test_same_basename_is_rejected_and_relative_suffix_resolves_source():
    paths,truth=fixture()
    paths.append(dict(id='other',timeline=[dict(file='/data/other/auth.log',offset=1,tech='T1110.001',stage=0)]))
    with pytest.raises(ValueError,match='Ambiguous'):score(paths,truth)
    for step in truth['attacks'][0]['steps']:step['file']='/data/auth.log'
    assert score(paths,truth)['attack_paths']==1
    paths,truth=fixture()
    for e in paths[0]['timeline']:e['file']='C:\\logs\\team\\auth.log'
    for s in truth['attacks'][0]['steps']:s['file']='team/auth.log'
    assert score(paths,truth)['attack_paths']==1


@pytest.mark.parametrize('fault',['empty','duplicate_id','duplicate_step','negative_offset','boolean_offset','bad_technique','bad_stage','conflicting_benign','boolean_flag'])
def test_malformed_truth_fails_closed(fault):
    paths,truth=fixture()
    if fault=='empty':truth['attacks']=[]
    elif fault=='duplicate_id':truth['attacks'].append(copy.deepcopy(truth['attacks'][0]))
    elif fault=='duplicate_step':truth['attacks'][0]['steps'].append(copy.deepcopy(truth['attacks'][0]['steps'][0]))
    elif fault=='negative_offset':truth['attacks'][0]['steps'][0]['offset']=-1
    elif fault=='boolean_offset':truth['attacks'][0]['steps'][0]['offset']=True
    elif fault=='bad_technique':truth['attacks'][0]['steps'][0]['technique']='guessing'
    elif fault=='bad_stage':truth['attacks'][0]['steps'][0]['stage']=5
    elif fault=='conflicting_benign':truth['benign']=[dict(file='auth.log',offset=1)]
    else:truth['exhaustive_steps']='true'
    with pytest.raises(ValueError):validate_truth(truth)


def gate_fixture():
    return dict(detection=1,labels=1,stages=1,stage_coverage=1,attack_paths=1,false_alarms=0,
        exact_membership_checked=True,p95_ms=100,stats=dict(cold_run=True,bytes=50_000_000_000,seconds=3500,cgroup_peak_bytes=7_000_000_000))


@pytest.mark.parametrize('field,value',[
    ('detection',.9),('labels',.85),('false_alarms',.1),('attack_paths',.9),
    ('exact_membership_checked',False),('p95_ms',500),('p95_ms',None),
    ('cold_run',False),('bytes',49_999_999_999),('bytes',None),('seconds',3600),('seconds',0),('seconds',None),
    ('false_alarms',-.1),('p95_ms',-1),('detection',True),
    ('cgroup_peak_bytes',None),('cgroup_peak_bytes',8_000_000_000),('synthetic_benchmark',True)])
def test_release_gate_rejects_each_failed_or_missing_requirement(field,value):
    result=gate_fixture()
    assert release_gate(result,{'synthetic':False})=='PASS' # Positive unit fixture, not a measured benchmark.
    target=result['stats'] if field in ('cold_run','bytes','seconds','cgroup_peak_bytes','synthetic_benchmark') else result
    target[field]=value
    assert release_gate(result,{'synthetic':False})!='PASS'


def test_synthetic_truth_never_certifies_the_real_release_gate():
    assert release_gate(gate_fixture(),{'synthetic':True})!='PASS'


def test_cli_evaluation_through_actual_api_in_an_isolated_database(tmp_path,monkeypatch,capsys):
    from backend.validation import validate
    from backend.api import app
    from fastapi.testclient import TestClient
    folder=tmp_path/'scenario';validate(folder,background=20)
    monkeypatch.setattr('backend.store.DB_PATH',str(folder/'validation.duckdb'))
    monkeypatch.delenv('API_TOKEN',raising=False)
    monkeypatch.setattr(sys,'argv',['evaluate','--truth',str(folder/'truth.json'),'--url','http://validation/api'])
    with TestClient(app) as client:
        class Session:
            def __init__(self):self.headers={}
            def get(self,url,**kwargs):return client.get(url.removeprefix('http://validation/api'),headers=self.headers)
        monkeypatch.setattr('backend.evaluate.requests.Session',Session)
        assert main()==1
    result=json.loads(capsys.readouterr().out)
    assert result['detection']==result['labels']==result['stages']==result['attack_paths']==1
    assert result['false_alarms']==1/3
    assert result['great_gate']!='PASS' and result['accuracy_scope']=='SYNTHETIC SCENARIO ONLY'
