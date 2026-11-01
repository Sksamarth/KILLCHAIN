"""Behavioral coverage and counterexamples for the requested eleven techniques."""
import json
from pathlib import Path

import pytest

from backend.formats import endpoint, timestamp
from backend.rules import ROOT, RuleEngine
from backend.scanner import materialize, ranges, scan_range
from backend.store import connect, records

BASE = 1792745306


def event(n=0, **fields):
    return (json.dumps(dict(timestamp=BASE+n,host='server1',**fields))+'\n').encode()


def matched(line):
    return {a['rule_id']:a for a in RuleEngine().candidates(line,'source.log',7)}


def reduce(tmp_path, lines, chunk_size=500):
    folder=tmp_path/'logs';folder.mkdir()
    # Both file and chunk boundaries must preserve threshold/cadence detections.
    middle=max(1,len(lines)//2)
    (folder/'a.jsonl').write_bytes(b''.join(lines[:middle]))
    (folder/'b.jsonl').write_bytes(b''.join(lines[middle:]))
    outputs=[]
    for i,task in enumerate(ranges(folder,chunk_size)):
        output=str(tmp_path/f'part{i}.parquet')
        scan_range((*task,output,str(ROOT/'rules/detect.yaml')));outputs.append(output)
    with connect(tmp_path/'coverage.duckdb') as db:
        materialize(db,outputs)
        return records(db.execute('SELECT * FROM alerts ORDER BY ts')),records(db.execute('SELECT * FROM alert_evidence'))


def test_endpoint_guessing_and_spraying_across_files(tmp_path):
    lines=[event(n,event_type='login_failure',user='admin',src_ip='198.51.100.1') for n in range(20)]
    lines += [event(30+n,event_type='login_failure',user=f'user{n}',src_ip='198.51.100.2') for n in range(10)]
    alerts,evidence=reduce(tmp_path,lines)
    by_id={a['rule_id']:a for a in alerts}
    assert by_id['R101']['count']==20 and by_id['R101']['user']=='admin'
    assert by_id['R102']['count']==10 and by_id['R102']['src_ip']=='198.51.100.2'
    assert len(evidence)==30 and all(e['offset']>=0 and Path(e['file']).exists() for e in evidence)


def test_spraying_does_not_merge_different_source_ips(tmp_path):
    alerts,_=reduce(tmp_path,[event(n,event_type='login_failure',user=f'user{n}',src_ip=f'198.51.100.{n+1}') for n in range(10)])
    assert not alerts


@pytest.mark.parametrize('src,remote,expected',[
    ('198.51.100.1',True,{'R110'}),('172.16.1.2',True,{'R111'}),
    ('192.168.1.2',True,{'R111'}),('10.1.1.1',False,set()),('not-an-ip',True,set()),
])
def test_successful_external_and_internal_remote_logins(src,remote,expected):
    assert set(matched(event(event_type='login_success',user='alice',src_ip=src,remote=remote)))==expected
    assert not matched(event(event_type='login_success',user='alice',src_ip=src,remote=remote,status='failure'))


def test_port_discovery_counts_distinct_ports(tmp_path):
    alerts,_=reduce(tmp_path,[event(n,event_type='flow',src_ip='192.168.1.1',dst_ip='172.16.1.1',dst_port=1000+n) for n in range(15)])
    assert [a['rule_id'] for a in alerts]==['R120']
    assert alerts[0]['count']==15


def test_repeated_one_port_is_not_service_discovery(tmp_path):
    alerts,_=reduce(tmp_path,[event(n,event_type='flow',src_ip='10.1.1.1',dst_ip='10.1.1.2',dst_port=22) for n in range(20)])
    assert not alerts


@pytest.mark.parametrize('command,rule',[
    ('/usr/sbin/useradd -m alice','R131'),('net user alice secret /add','R131'),
    (r'C:\Windows\System32\net.exe user alice secret /add','R131'),
    ('sudo id','R140'),('sudo -u root /usr/bin/id','R140'),('sudo --user=root id','R140'),
    ('tar -czf /tmp/data.tgz /home/alice','R150'),('tar cf data.tar /tmp/data','R150'),
    ('zip data.zip /tmp/data','R150'),('rar a data.rar /tmp/data','R150'),('7z a data.7z /tmp/data','R150'),
    ('history -c','R181'),('bash -c "history -c"','R181'),
    ('wevtutil cl Security','R182'),('Clear-EventLog -LogName Security','R182'),
    ('rm /var/log/auth.log','R183'),('journalctl --vacuum-time=1s','R183'),
])
def test_endpoint_commands(command,rule):
    alerts=matched(event(event_type='process',command=command,user='alice'))
    assert rule in alerts
    assert alerts[rule]['file']=='source.log' and alerts[rule]['offset']==7 and alerts[rule]['host']=='server1'


@pytest.mark.parametrize('command',[
    'echo "useradd alice"','echo "history -c"','echo "tar -czf data.tgz /home"',
    'useradd --help','net user alice /delete','net user alice secret /add /domain',
    'sudo -u nobody id','sudo --user=nobody id','sudo -l','sudo -v',
    'tar -tf data.tar','tar -xf data.tar','tar -C /tmp -tf data.tar','zip -d data.zip file','7z l data.7z',
    'history','wevtutil el','rm /tmp/temporary.log',
])
def test_benign_commands_do_not_match(command):
    assert not matched(event(event_type='process',command=command,user='alice'))


def test_windows_events_and_xml():
    create=event(event_id=4720,TargetUserName='newaccount',SubjectUserName='admin',TargetDomainName='SERVER1')
    alert=matched(create)['R130']
    assert alert['technique']=='T1136.001' and alert['new_user']=='newaccount' and alert['user']=='admin'
    assert matched(event(event_id=1102,SubjectUserName='admin'))['R180']['technique']=='T1070.001'
    privileges=matched(event(event_id=4672,SubjectUserName='admin'))
    assert set(privileges)=={'R141'} and privileges['R141']['technique']!='T1548.003'
    xml=b'<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>4720</EventID><TimeCreated SystemTime="2026-10-23T03:18:26Z"/><Computer>server1</Computer></System><EventData><Data Name="SubjectUserName">admin</Data><Data Name="TargetUserName">newaccount</Data><Data Name="TargetDomainName">SERVER1</Data></EventData></Event>'
    assert matched(xml)['R130']['new_user']=='newaccount'
    winlog=event(**{'winlog':{'event_id':4624,'computer_name':'server1','event_data':{'TargetUserName':'alice','IpAddress':'::ffff:172.16.1.2','LogonType':'10'}}})
    assert matched(winlog)['R111']['src_ip']=='172.16.1.2'
    assert 'R131' in matched(event(event_id=4688,CommandLine='net user alice secret /add'))


def test_linux_auth_sudo_and_user_creation():
    prefix='2026-10-23T03:18:26Z server1 '
    assert 'R110' in matched((prefix+'sshd[12]: Accepted password for alice from 198.51.100.1 port 22 ssh2').encode())
    assert 'R111' in matched((prefix+'sshd[12]: Accepted publickey for alice from 172.16.1.2 port 22 ssh2').encode())
    assert 'R140' in matched((prefix+'sudo: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/id').encode())
    assert 'R130' in matched((prefix+'useradd[12]: new user: name=bob, UID=1002, GID=1002').encode())


@pytest.mark.parametrize('bytes_sent,destination,expected',[
    (99999999,'198.51.100.2',False),(100000000,'198.51.100.2',True),
    (100000000,'172.16.1.2',False),(100000000,'invalid',False),
])
def test_large_outbound_transfer(bytes_sent,destination,expected):
    alerts=matched(event(event_type='flow',src_ip='192.168.1.1',dst_ip=destination,bytes=bytes_sent,dst_port=443,protocol='https'))
    assert ('R160' in alerts)==expected


def test_periodic_small_beacon_across_boundaries(tmp_path):
    lines=[event(n*60,event_type='flow',src_ip='10.1.1.1',dst_ip='198.51.100.1',dst_port=443,protocol='https',bytes=200) for n in range(12)]
    alerts,evidence=reduce(tmp_path,lines)
    assert len(alerts)==1 and alerts[0]['rule_id']=='R170' and alerts[0]['count']==12
    assert len(evidence)==12


@pytest.mark.parametrize('times,size',[
    ([0,5,10,30,40,100,120,200,250,500,600,900],200),
    ([n*60 for n in range(12)],4097),([n*60 for n in range(9)],200),
    ([0]*12,200),([n*700 for n in range(12)],200),
])
def test_nonbeacons_do_not_trigger(tmp_path,times,size):
    alerts,_=reduce(tmp_path,[event(n,event_type='flow',src_ip='10.1.1.1',dst_ip='198.51.100.1',dst_port=443,protocol='https',bytes=size) for n in times])
    assert not alerts


def test_unsupported_and_malformed_lines_are_counted(tmp_path):
    f=tmp_path/'invalid.jsonl';f.write_bytes(b'{bad json}\nOct 23 03:18:26 host sshd: Accepted password for alice from 10.1.1.1\n'+event(event_type='process',command='echo ok'))
    out=str(tmp_path/'invalid.parquet')
    result=scan_range((*next(ranges(f)),out,str(ROOT/'rules/detect.yaml')))
    assert result['lines']==3 and result['unsupported_lines']==2
    assert timestamp('2026-10-23T03:18:26') is None
    assert timestamp('2026-10-23T03:18:26Z')==1792725506
    assert endpoint(b'{"timestamp":true}') is None


def test_identity_escaping_does_not_change_canonical_fields():
    alert=matched(event(event_type='login_success',src_ip='198.51.100.1',user='a" dst_ip="10.9.9.9'))['R110']
    assert alert['user']=='a" dst_ip="10.9.9.9' and alert['dst_ip']==''


def fortigate_flow(n,port=443,size=200,dst='198.51.100.1'):
    return (f'eventtime={(BASE+n)*1000000000} type="traffic" srcip=172.16.1.2 srcport=50000 srcintf="lan" srcintfrole="lan" dstip={dst} dstport={port} action="accept" sentbyte={size}\n').encode()


def test_fortigate_cadence_and_non_10_private_networks(tmp_path):
    alerts,evidence=reduce(tmp_path,[fortigate_flow(n*60) for n in range(12)])
    assert len(alerts)==1 and alerts[0]['rule_id']=='R052' and len(evidence)==12
    assert 'R040' in matched(fortigate_flow(0,size=100000000))
    assert 'R040' not in matched(fortigate_flow(0,size=100000000,dst='192.168.1.1'))
    assert 'R033' in matched(fortigate_flow(0,port=22,dst='192.168.1.1'))


def test_fortigate_source_ip_spray_and_port_discovery(tmp_path):
    lines=[(f'eventtime={(BASE+n)*1000000000} logdesc="Admin login failed" user="user{n}" ui="https(x)" method="https" srcip=198.51.100.1 srcintf="wan" srcintfrole="wan" dstip=10.1.1.1 reason="passwd_invalid"\n').encode() for n in range(10)]
    lines += [fortigate_flow(30+n,port=1000+n,dst='192.168.1.1') for n in range(15)]
    alerts,_=reduce(tmp_path,lines)
    ids={a['rule_id'] for a in alerts}
    assert {'R002','R020'} <= ids


def test_windows_account_scope_is_not_guessed():
    assert set(matched(event(event_id=4720,TargetUserName='alice',TargetDomainName='CORP')))=={'R133'}
    assert set(matched(event(event_id=4720,TargetUserName='alice')))=={'R132'}


def test_endpoint_chain_publishes_reports_and_evidence(tmp_path):
    from backend.scanner import run
    path=tmp_path/'chain.jsonl'
    lines=[event(n,event_type='login_failure',user='alice',src_ip='198.51.100.1') for n in range(20)]
    lines += [event(25,event_type='login_success',user='alice',src_ip='198.51.100.1',dst_ip='10.1.1.1'),
              event(30,event_type='process',user='alice',command='sudo tar -czf data.tgz /home/alice'),
              event(40,event_type='flow',user='alice',src_ip='10.1.1.1',dst_ip='198.51.100.1',dst_port=443,bytes=100000000),
              event(45,event_type='process',user='alice',command='history -c')]
    path.write_bytes(b''.join(lines));dbpath=tmp_path/'chain.duckdb'
    result=run(path,db_path=dbpath,workers=1,chunk_size=500)
    assert result['lines']==24 and result['unsupported_lines']==0
    with connect(dbpath) as db:
        paths=[json.loads(row[0]) for row in db.execute("SELECT path_json FROM incident_paths WHERE status='active'").fetchall()]
        techniques={step['tech'] for path in paths for step in path['timeline']}
        assert {'T1110.001','T1078','T1548.003','T1560','T1041','T1070.003'} <= techniques
        assert any('endpoint_brute_force_then_login' in path['sequence_ids'] for path in paths)
        assert any('endpoint_login_then_exfiltration' in path['sequence_ids'] for path in paths)
        assert all(path['report'] for path in paths)
        assert db.execute('SELECT count(*) FROM alert_evidence').fetchone()[0]>=24
