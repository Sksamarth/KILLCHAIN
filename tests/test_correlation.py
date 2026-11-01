from backend.correlate import components


CONFIG = dict(stoplist=[], entity_degree_cap=2, max_gap_seconds=60,
              max_incident_span_seconds=180, compound_entities=True)


def event(i, host='', user='', src='', dst='', end=None):
    return dict(alert_id=str(i), first_ts=i, last_ts=i if end is None else end,
                file='events.log', offset=i, host=host, user=user, src_ip=src, dst_ip=dst)


def memberships(rows, config=CONFIG):
    return {frozenset(a['alert_id'] for a in group) for group in components(rows, config)}


def test_busy_host_and_account_keep_joint_context_without_merging_other_hosts():
    rows = [event(i, host=host, user='admin')
            for i,host in enumerate(['HR-07','FS-02','HR-07','FS-02','HR-07','FS-02'])]
    assert memberships(rows) == {frozenset(['0','2','4']),frozenset(['1','3','5'])}


def test_shared_hub_ip_does_not_join_different_host_account_pairs():
    rows = [event(i,host='shared-server',user=user,src='198.51.100.1')
            for i,user in enumerate(['alice','bob','alice','bob','alice','bob'])]
    assert memberships(rows) == {frozenset(['0','2','4']),frozenset(['1','3','5'])}


def test_lateral_movement_joins_source_and_destination_roles():
    rows = [event(0,host='HR-07',user='alice',src='198.51.100.1',dst='10.0.0.7'),
            event(10,host='FS-02',user='alice',src='10.0.0.7',dst='10.0.0.2'),
            event(20,host='DC-01',user='alice',src='10.0.0.2',dst='10.0.0.1')]
    assert memberships(rows) == {frozenset(['0','10','20'])}
    assert memberships(rows[::-1]) == memberships(rows)


def test_continuous_activity_is_bounded_by_incident_span():
    rows = [event(i,host='server',user='admin') for i in range(0,501,50)]
    groups = components(rows, CONFIG)
    assert len(groups)>1
    assert sum(map(len,groups))==len(rows)
    assert all(max(a['last_ts'] for a in group)-min(a['first_ts'] for a in group)<=180 for group in groups)


def test_overlapping_aggregate_keeps_long_interval_for_later_event():
    rows = [event(0,user='alice',end=100),event(10,user='alice'),event(150,user='alice')]
    config = dict(CONFIG,entity_degree_cap=10)
    assert memberships(rows,config) == {frozenset(['0','10','150'])}


def test_compound_context_respects_stoplist_and_can_be_disabled():
    rows = [event(i,host='hub',user='admin') for i in range(4)]
    assert len(components(rows,dict(CONFIG,compound_entities=False)))==4
    assert len(components(rows,dict(CONFIG,stoplist=['admin'])))==4


def test_created_account_connects_to_later_account_use():
    created = event(0,host='HR-07',user='admin')
    created['new_user']='backdoor'
    used = event(10,host='FS-02',user='backdoor')
    assert memberships([created,used]) == {frozenset(['0','10'])}


def test_same_pair_after_idle_gap_starts_new_incident():
    rows = [event(i,host='server',user='admin') for i in (0,10,20,100,110,120)]
    assert memberships(rows) == {frozenset(['0','10','20']),frozenset(['100','110','120'])}
