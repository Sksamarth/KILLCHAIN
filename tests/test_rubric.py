import pytest

from backend.rubric import scorecard


def measured():
    return dict(detection=1, labels=1, attack_paths=1, false_alarms=0,
                exact_membership_checked=True, p95_ms=100,
                stats=dict(cold_run=True, bytes=50_000_000_000, seconds=3500,
                           cgroup_peak_bytes=7_000_000_000))


@pytest.mark.parametrize('field,metric,value,good,great', [
    ('detection','detection',.70,'FAIL','FAIL'),
    ('detection','detection',.90,'PASS','FAIL'),
    ('detection','detection',.90001,'PASS','PASS'),
    ('labels','correct_labels',.60,'FAIL','FAIL'),
    ('labels','correct_labels',.85,'PASS','FAIL'),
    ('labels','correct_labels',.85001,'PASS','PASS'),
    ('attack_paths','attack_path',.499,'FAIL','FAIL'),
    ('attack_paths','attack_path',.50,'PASS','FAIL'),
    ('attack_paths','attack_path',1,'PASS','PASS'),
    ('false_alarms','false_alarms',.30,'FAIL','FAIL'),
    ('false_alarms','false_alarms',.10,'PASS','FAIL'),
    ('false_alarms','false_alarms',.09999,'PASS','PASS'),
    ('seconds','processing_time',10800,'FAIL','FAIL'),
    ('seconds','processing_time',3600,'PASS','FAIL'),
    ('seconds','processing_time',3599,'PASS','PASS'),
    ('cgroup_peak_bytes','memory',16_000_000_000,'FAIL','FAIL'),
    ('cgroup_peak_bytes','memory',8_000_000_000,'PASS','FAIL'),
    ('cgroup_peak_bytes','memory',7_999_999_999,'PASS','PASS'),
    ('p95_ms','investigation_speed',2000,'FAIL','FAIL'),
    ('p95_ms','investigation_speed',500,'PASS','FAIL'),
    ('p95_ms','investigation_speed',499,'PASS','PASS'),
])
def test_exact_rubric_boundaries(field,metric,value,good,great):
    result=measured()
    (result['stats'] if field in result['stats'] else result)[field]=value
    report=scorecard(result,{'synthetic':False})['metrics'][metric]
    assert (report['good'],report['great'])==(good,great)


@pytest.mark.parametrize('value',[None,True,-1,float('nan'),float('inf'),1.01])
def test_invalid_accuracy_never_grades_as_pass(value):
    result=measured();result['detection']=value
    report=scorecard(result,{})
    assert report['metrics']['detection']['great']=='UNVERIFIED'
    assert report['overall_great']=='UNVERIFIED'


def test_chosen_tier_does_not_extrapolate_small_or_resumed_scans():
    result=measured();result['stats']['bytes']=15_000_000_000
    assert scorecard(result,{},50)['metrics']['processing_time']['great']=='UNVERIFIED'
    assert scorecard(result,{},15)['overall_great']=='PASS'
    result['stats']['cold_run']=False
    assert scorecard(result,{},15)['metrics']['memory']['great']=='UNVERIFIED'


def test_synthetic_and_missing_truth_cannot_certify():
    assert scorecard(measured(),{'synthetic':True})['overall_great']=='UNVERIFIED'
    report=scorecard(measured(),None)
    assert report['overall_good']=='UNVERIFIED'
    assert report['metrics']['detection']['great']=='UNVERIFIED'
    assert len(report['metrics'])==7


def test_failures_remain_visible_when_other_evidence_is_missing():
    result=measured();result['false_alarms']=1/3;result['stats']['bytes']=1000
    report=scorecard(result,{'synthetic':True})
    assert report['overall_good']==report['overall_great']=='FAIL'
    assert report['metrics']['processing_time']['great']=='UNVERIFIED'


@pytest.mark.parametrize('tier',[0,-1,True,float('nan'),float('inf')])
def test_invalid_tier_rejected(tier):
    with pytest.raises(ValueError):scorecard({},None,tier)
