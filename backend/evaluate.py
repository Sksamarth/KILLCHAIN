"""Ground-truth gate. Missing truth is NOT a pass.

Schema: {attacks:[{id,steps:[{file,offset,technique}]}]}.
File is a basename or path, offset an exact raw byte offset. Steps are ordered.
"""
import argparse
import json
import os
import statistics
import time
from pathlib import Path

import requests


def score(paths, truth, evidence=None):
    found=correct=parent_correct=total=rebuilt=0
    matched_incidents=set(); breakdown=[]
    for attack in truth['attacks']:
        ordered=[]; detail=[]
        for step in attack['steps']:
            total+=1
            linked={r['alert_id'] for r in (evidence or {}).get((step['file'],step['offset']),[])}
            hits=[(p,i,e) for p in paths for i,e in enumerate(p['timeline'])
                  if (e.get('alert_id') in linked if evidence is not None else Path(e['file']).name==Path(step['file']).name and e['offset']==step['offset'])]
            hit=next((h for h in hits if h[2]['tech']==step['technique']),hits[0] if hits else None)
            if hit:
                p,i,e=hit; found+=1; correct+=e['tech']==step['technique']; parent_correct+=e['tech'].split('.')[0]==step['technique'].split('.')[0]
                matched_incidents.add(p['id']); ordered.append((p['id'],i,e['tech']==step['technique']))
            detail.append(dict(step=step,found=bool(hit),correct=bool(hit and hit[2]['tech']==step['technique'])))
        ok=bool(ordered) and len(ordered)==len(attack['steps']) and len({x[0] for x in ordered})==1 and all(x[2] for x in ordered) and all(a[1]<b[1] for a,b in zip(ordered,ordered[1:]))
        rebuilt+=ok; breakdown.append(dict(attack=attack['id'],rebuilt=ok,steps=detail))
    return dict(detection=found/total if total else None,labels=correct/found if found else None,parent_labels=parent_correct/found if found else None,
                attack_paths=rebuilt/len(truth['attacks']) if truth['attacks'] else None,false_alarms=(len(paths)-len(matched_incidents))/len(paths) if paths else None,breakdown=breakdown)


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--truth',default=os.environ.get('GROUND_TRUTH','/data/ground_truth/attacks.json'));parser.add_argument('--url',default=os.environ.get('API_URL','http://frontend/api'))
    args=parser.parse_args()
    session=requests.Session()
    if os.environ.get('API_TOKEN'): session.headers['Authorization']='Bearer '+os.environ['API_TOKEN']
    def get(endpoint):
        r=session.get(args.url+endpoint,timeout=60);r.raise_for_status();return r.json()
    incidents=[];offset=0
    while True:
        page=get(f'/incidents?limit=500&offset={offset}')
        incidents+=page
        if len(page)<500:break
        offset+=500
    paths=[];latency=[]
    for incident in incidents:
        start=time.perf_counter();paths.append(get(f'/incidents/{incident["id"]}/path'));latency.append((time.perf_counter()-start)*1000)
    result={'stats':get('/stats'),'p50_ms':statistics.median(latency) if latency else None,'p95_ms':sorted(latency)[max(0,int(len(latency)*.95+.999)-1)] if latency else None}
    if not Path(args.truth).exists():
        result.update(accuracy_status='NOT MEASURED: no ground truth supplied',great_gate='UNVERIFIED');print(json.dumps(result,indent=2));return 2
    truth=json.loads(Path(args.truth).read_text())
    if not truth.get('attacks') or any(not a.get('steps') for a in truth['attacks']): raise ValueError('Ground truth must contain nonempty attacks and ordered steps')
    from urllib.parse import urlencode
    evidence={}
    for attack in truth['attacks']:
        for step in attack['steps']:
            key=(step['file'],step['offset'])
            if key not in evidence: evidence[key]=get('/evidence?'+urlencode(dict(file=key[0],offset=key[1])))
    result.update(score(paths,truth,evidence))
    result['great_gate']='PASS' if (result['detection'] is not None and result['detection']>.90 and result['labels']>.85 and result['attack_paths']==1 and result['false_alarms'] is not None and result['false_alarms']<.10 and result['p95_ms']<500 and result['stats'].get('cold_run') is True and not result['stats'].get('synthetic_benchmark',False) and result['stats'].get('bytes',0)>=50_000_000_000 and result['stats']['seconds']<3600 and 0<(result['stats'].get('cgroup_peak_bytes') or 0)<8_000_000_000) else 'FAIL OR UNVERIFIED'
    print(json.dumps(result,indent=2));return 0 if result['great_gate']=='PASS' else 1


if __name__=='__main__': raise SystemExit(main())
