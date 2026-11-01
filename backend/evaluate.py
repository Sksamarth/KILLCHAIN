"""Ground-truth gate. Missing truth is NOT a pass.

Schema: {attacks:[{id,steps:[{file,offset,technique}]}]}.
File is a basename or path, offset an exact raw byte offset. Steps are ordered.
"""
import argparse
import json
import os
import re
import statistics
import time
from pathlib import Path

import requests
from backend.rubric import scorecard


def validate_truth(truth):
    if not isinstance(truth,dict) or not isinstance(truth.get('attacks'),list) or not truth['attacks']:
        raise ValueError('Ground truth must contain nonempty attacks and ordered steps')
    ids=set();seen=set()
    for attack in truth['attacks']:
        if not isinstance(attack,dict) or not isinstance(attack.get('id'),str) or not attack['id'] or attack['id'] in ids:
            raise ValueError('Ground-truth attack IDs must be unique nonempty strings')
        ids.add(attack['id'])
        if not isinstance(attack.get('steps'),list) or not attack['steps']:raise ValueError('Each attack needs ordered steps')
        for step in attack['steps']:
            if not isinstance(step,dict) or not isinstance(step.get('file'),str) or not step['file'] or type(step.get('offset')) is not int or step['offset']<0:
                raise ValueError('Every step needs a source file and nonnegative integer byte offset')
            if not isinstance(step.get('technique'),str) or not re.fullmatch(r'T\d{4}(?:\.\d{3})?',step['technique']):raise ValueError('Every step needs an ATT&CK technique ID')
            if 'stage' in step and (type(step['stage']) is not int or step['stage'] not in range(5)):raise ValueError('Expected stage must be an integer from 0 to 4')
            key=(step['file'].replace('\\','/'),step['offset'],step['technique'])
            if key in seen:raise ValueError('Duplicate ground-truth step; independent attacks must not share the same labelled step')
            seen.add(key)
    for flag in ('synthetic','exhaustive_steps'):
        if flag in truth and type(truth[flag]) is not bool:raise ValueError(flag+' must be boolean')
    if not isinstance(truth.get('benign',[]),list):raise ValueError('Benign references must be a list')
    attack_lines={(file,offset) for file,offset,technique in seen}
    for reference in truth.get('benign',[]):
        if not isinstance(reference,dict) or not isinstance(reference.get('file'),str) or not reference['file'] or type(reference.get('offset')) is not int or reference['offset']<0:
            raise ValueError('Every benign reference needs a source file and nonnegative integer byte offset')
        if (reference['file'].replace('\\','/'),reference['offset']) in attack_lines:raise ValueError('A source line cannot be both a planted step and known benign')


def source_matches(actual,reference):
    actual=str(actual).replace('\\','/');reference=str(reference).replace('\\','/')
    if re.match(r'^[a-zA-Z]:/',reference):return actual.casefold()==reference.casefold()
    if reference.startswith('/'):return actual==reference
    reference=reference.removeprefix('./')
    return actual==reference or actual.endswith('/'+reference)


def score(paths, truth, evidence=None):
    validate_truth(truth)
    found=correct=parent_correct=total=rebuilt=0
    matched_incidents=set(); breakdown=[]; incident_attacks={};covered=set();stage_total=stage_found=stage_correct=0
    positions=[(p,i,e) for p in paths for i,e in enumerate(p['timeline'])]
    files={e['file'] for _,_,e in positions}
    if evidence is not None:files.update(r['file'] for rows in evidence.values() for r in rows if r.get('file'))
    by_alert={};by_offset={}
    for hit in positions:
        by_alert.setdefault(hit[2].get('alert_id'),[]).append(hit)
        by_offset.setdefault(hit[2]['offset'],[]).append(hit)
    def hits_for(step):
        if len({str(f).replace('\\','/') for f in files if source_matches(f,step['file'])})>1:
            raise ValueError('Ambiguous source reference '+step['file']+'; provide a unique relative or absolute file path')
        if evidence is not None:
            linked={r['alert_id'] for r in evidence.get((step['file'],step['offset']),[])}
            return [hit for aid in sorted(linked) for hit in by_alert.get(aid,[])]
        return [hit for hit in by_offset.get(step['offset'],[]) if source_matches(hit[2]['file'],step['file'])]
    for attack in truth['attacks']:
        ordered=[]; detail=[]
        for step in attack['steps']:
            total+=1
            hits=hits_for(step)
            hit=next((h for h in hits if h[2]['tech']==step['technique']),hits[0] if hits else None)
            if hit and hit[2]['tech']==step['technique']:covered.add((str(hit[0]['id']),hit[1]))
            stage_ok=bool(hit and ('stage' not in step or hit[2].get('stage')==step['stage']))
            if 'stage' in step:
                stage_total+=1;stage_found+=bool(hit);stage_correct+=stage_ok
            if hit:
                p,i,e=hit; found+=1; correct+=e['tech']==step['technique']; parent_correct+=e['tech'].split('.')[0]==step['technique'].split('.')[0]
                matched_incidents.add(p['id']); ordered.append((p['id'],i,e['tech']==step['technique'] and stage_ok))
            detail.append(dict(step=step,found=bool(hit),correct=bool(hit and hit[2]['tech']==step['technique']),stage_correct=stage_ok if 'stage' in step else None))
        ok=bool(ordered) and len(ordered)==len(attack['steps']) and len({x[0] for x in ordered})==1 and all(x[2] for x in ordered) and all(a[1]<b[1] for a,b in zip(ordered,ordered[1:]))
        for incident_id in {x[0] for x in ordered}:
            incident_attacks.setdefault(incident_id,set()).add(attack['id'])
        breakdown.append(dict(attack=attack['id'],rebuilt=ok,steps=detail,incident_ids=sorted({str(x[0]) for x in ordered})))
    # Sharing one incident between independent planted attacks is not a rebuilt path.
    merged={incident_id for incident_id,attacks in incident_attacks.items() if len(attacks)>1}
    affected=set().union(*(incident_attacks[i] for i in merged)) if merged else set()
    unexpected={str(p['id']) for p,i,e in positions if (str(p['id']),i) not in covered}
    contaminated={str(p['id']) for step in truth.get('benign',[]) for p,i,e in hits_for(step)}
    for attack in breakdown:
        attack['merged_with_other_attack']=attack['attack'] in affected
        attack['rebuilt']=attack['rebuilt'] and not attack['merged_with_other_attack']
        attack['known_benign_in_path']=bool(set(attack['incident_ids'])&contaminated)
        attack['unexpected_steps']=bool(set(attack['incident_ids'])&unexpected)
        attack['rebuilt']=attack['rebuilt'] and not attack['known_benign_in_path'] and not (truth.get('exhaustive_steps') is True and attack['unexpected_steps'])
    rebuilt=sum(attack['rebuilt'] for attack in breakdown)
    return dict(detection=found/total if total else None,labels=correct/found if found else None,parent_labels=parent_correct/found if found else None,
                stages=stage_correct/stage_found if stage_found else None,stage_coverage=stage_total/total if total else 0,
                exact_membership_checked=truth.get('exhaustive_steps') is True,known_benign_incidents=len(contaminated),
                unmatched_detections=sum((str(p['id']),i) not in covered for p,i,e in positions),
                attack_paths=rebuilt/len(truth['attacks']) if truth['attacks'] else None,false_alarms=(len(paths)-len(matched_incidents))/len(paths) if paths else None,merged_incidents=len(merged),breakdown=breakdown)


def release_gate(result,truth,tier_gb=50):
    return scorecard(result,truth,tier_gb)['overall_great']


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--truth',default=os.environ.get('GROUND_TRUTH','/data/ground_truth/attacks.json'));parser.add_argument('--url',default=os.environ.get('API_URL','http://frontend/api'))
    parser.add_argument('--tier-gb',type=float,default=50,help='Full chosen tier in decimal GB (default: Extreme 50 GB)')
    args=parser.parse_args()
    try:scorecard({},None,args.tier_gb)
    except ValueError as exc:parser.error(str(exc))
    if not Path(args.truth).exists():
        print(json.dumps(dict(accuracy_status='NOT MEASURED: no ground truth supplied',great_gate='UNVERIFIED',rubric=scorecard({},None,args.tier_gb)),indent=2))
        return 2
    truth=json.loads(Path(args.truth).read_text())
    validate_truth(truth)
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
    from urllib.parse import urlencode
    evidence={}
    for attack in truth['attacks']:
        for step in attack['steps']:
            key=(step['file'],step['offset'])
            if key not in evidence: evidence[key]=get('/evidence?'+urlencode(dict(file=key[0],offset=key[1])))
    for step in truth.get('benign',[]):
        key=(step['file'],step['offset'])
        if key not in evidence:evidence[key]=get('/evidence?'+urlencode(dict(file=key[0],offset=key[1])))
    result.update(score(paths,truth,evidence))
    result['rubric']=scorecard(result,truth,args.tier_gb)
    result['great_gate']=result['rubric']['overall_great']
    result['accuracy_scope']='SYNTHETIC SCENARIO ONLY' if truth.get('synthetic') else 'Supplied independent truth; provenance must be reviewed'
    print(json.dumps(result,indent=2));return 0 if result['great_gate']=='PASS' else 1


if __name__=='__main__': raise SystemExit(main())
