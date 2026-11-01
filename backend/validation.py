"""Deterministic scenario validation in an isolated database, never live results.

Run: python -m backend.validation --output tmp/validation --seed 701
Truth is written before scanning. No detector/provider annotations enter truth.
"""
import argparse
import hashlib
import json
import random
from pathlib import Path

from backend.evaluate import score
from backend.scanner import run
from backend.store import connect,records

BASE=1792745306
# Authored expected display stages, independent of runtime YAML mappings.
EXPECTED_STAGES={'T1110.001':0,'T1110.003':0,'T1078':0,'T1136.001':1,
                 'T1548.003':3,'T1046':2,'T1021':3,'T1560':2,'T1041':4,'T1070.003':1,'T1071':1}


def generate(folder,seed=701,background=2000):
    folder=Path(folder);folder.mkdir(parents=True,exist_ok=True)
    file=folder/'scenarios.jsonl'
    rng=random.Random(seed);rows=[];attacks=[];benign=[]
    def add(seconds,host,user,technique=None,attack=None,benign_case=None,**fields):
        value=dict(timestamp=BASE+seconds,host=host,user=user,**fields)
        rows.append((value,technique,attack,benign_case))
    # Normal telemetry includes command lookalikes and repeated single-port flows.
    commands=['echo "history -c"','tar -tf backup.tar','sudo -u nobody id','wevtutil el','echo "useradd alice"']
    for i in range(background):
        host=f'normal-{i%20}';user=f'employee-{i%20}'
        add(rng.randrange(1200),host,user,benign_case='ordinary_telemetry',event_type='process',command=rng.choice(commands))
        if i%10==0:add(i%1200,host,user,benign_case='one_port_internal_flow',event_type='flow',src_ip='10.90.0.1',dst_ip='10.90.0.2',dst_port=22,bytes=8000)
    # Campaign 1: external guess, takeover, local account, sudo, discovery,
    # lateral movement, collection, transfer and cleanup across two hosts.
    a='credential-to-exfiltration';h=f'HR-{seed}';u='alice';source='198.51.100.31'
    for n in range(20):add(n,h,u,'T1110.001' if n==0 else None,a,event_type='login_failure',src_ip=source)
    add(30,h,u,'T1078',a,event_type='login_success',src_ip=source,remote=True)
    add(40,h,u,'T1136.001',a,event_type='account_create',new_user='support-shadow')
    add(50,h,u,'T1548.003',a,event_type='process',command='sudo id')
    for n in range(15):add(60+n,h,u,'T1046' if n==0 else None,a,event_type='flow',src_ip='10.60.0.7',dst_ip='10.60.0.2',dst_port=2000+n,bytes=8000)
    add(90,'FS-02',u,'T1021',a,event_type='login_success',src_ip='10.60.0.7',dst_ip='10.60.0.2',remote=True)
    add(100,'FS-02',u,'T1560',a,event_type='process',command='tar -czf collected.tgz /srv/files')
    add(110,'FS-02',u,'T1041',a,event_type='flow',src_ip='10.60.0.2',dst_ip='203.0.113.31',dst_port=443,bytes=150000000,protocol='https')
    add(120,'FS-02',u,'T1070.003',a,event_type='process',command='history -c')
    # Independent campaign: spraying and periodic application-layer beaconing.
    a='spray-to-beacon';h=f'ENG-{seed}'
    for n in range(10):add(300+n,h,f'target-{n}','T1110.003' if n==0 else None,a,event_type='login_failure',src_ip='198.51.100.92')
    add(330,h,'target-0','T1078',a,event_type='login_success',src_ip='198.51.100.92',remote=True)
    for n in range(10):add(360+n*30,h,'target-0','T1071' if n==0 else None,a,event_type='flow',src_ip='10.70.0.9',dst_ip='203.0.113.92',dst_port=443,bytes=512,protocol='https')
    # Contextual hard negative: legitimate backup resembles collection/exfiltration.
    # Its legitimacy belongs to truth, not to an undisclosed detector allowlist.
    add(700,'backup-01','svc_backup',benign_case='authorized_backup',event_type='process',command='tar -czf nightly.tgz /srv/team')
    add(710,'backup-01','svc_backup',benign_case='authorized_backup',event_type='flow',src_ip='10.80.0.5',dst_ip='203.0.113.200',dst_port=443,bytes=200000000,protocol='https')
    # Sort by event time; exact byte offsets are recorded during serialization.
    rows.sort(key=lambda r:r[0]['timestamp']);by_attack={}
    with file.open('wb') as handle:
        for value,technique,attack,case in rows:
            offset=handle.tell();handle.write((json.dumps(value,sort_keys=True)+'\n').encode())
            reference=dict(file=file.name,offset=offset)
            if technique:by_attack.setdefault(attack,[]).append(dict(**reference,technique=technique,stage=EXPECTED_STAGES[technique]))
            if case:benign.append(dict(**reference,case=case))
    attacks=[dict(id=key,steps=value) for key,value in by_attack.items()]
    truth=dict(schema_version=1,synthetic=True,exhaustive_steps=True,seed=seed,attacks=attacks,benign=benign,
               source_sha256=hashlib.sha256(file.read_bytes()).hexdigest(),
               provenance='Fixed authored scenarios; expected techniques and byte offsets saved before running the detector. No AI/provider-derived truth.')
    (folder/'truth.json').write_text(json.dumps(truth,indent=2),encoding='utf8')
    return file,truth


def validate(folder,seed=701,background=2000):
    folder=Path(folder);source,truth=generate(folder,seed,background)
    dbpath=folder/'validation.duckdb'
    stats=run(source,db_path=dbpath,workers=1,chunk_size=32768)
    with connect(dbpath) as db:
        paths=[json.loads(row[0]) for row in db.execute("SELECT path_json FROM incident_paths WHERE status='active'").fetchall()]
        evidence={}
        for item in truth['benign']+[step for attack in truth['attacks'] for step in attack['steps']]:
            evidence[(item['file'],item['offset'])]=records(db.execute('SELECT * FROM alert_evidence WHERE "offset"=?',[item['offset']]))
        active_alerts={event['alert_id'] for path in paths for event in path['timeline']}
        benign_hits=[dict(**line,alert_ids=[e['alert_id'] for e in evidence[(line['file'],line['offset'])] if e['alert_id'] in active_alerts]) for line in truth['benign']]
    result=score(paths,truth,evidence)
    failures=[line for line in benign_hits if line['alert_ids']]
    result.update(scope='Synthetic scenario validation only; not real-data accuracy or a 15/50 GB release pass',seed=seed,
        source_sha256=truth['source_sha256'],stats=stats,active_incidents=len(paths),
        benign_records=len(benign_hits),benign_records_in_active_incidents=len(failures),
        benign_record_false_positive_rate=len(failures)/len(benign_hits) if benign_hits else None,
        benign_failures=failures,
        accuracy_gate='PASS' if result['detection'] and result['detection']>.9 and result['labels']>.85 and result['stages']==1 and result['exact_membership_checked'] and result['attack_paths']==1 and result['false_alarms'] is not None and result['false_alarms']<.1 else 'FAIL')
    (folder/'results.json').write_text(json.dumps(result,indent=2),encoding='utf8')
    return result


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--output',default='tmp/validation');parser.add_argument('--seed',type=int,default=701);parser.add_argument('--background',type=int,default=2000)
    args=parser.parse_args();result=validate(args.output,args.seed,args.background)
    print(json.dumps({k:v for k,v in result.items() if k not in ('breakdown','benign_failures','stats')},indent=2))
    return 0 if result['accuracy_gate']=='PASS' else 1


if __name__=='__main__':raise SystemExit(main())
