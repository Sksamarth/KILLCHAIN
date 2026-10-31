"""Deterministic bounded sample profile; never claims full-dataset statistics."""
import argparse
import collections
import json
import random
from pathlib import Path

from backend.rules import KV


def profile(path, limit=200000):
    counts,examples=collections.Counter(),collections.defaultdict(list)
    sizes=[]; rng=random.Random(0); lines=0
    files=[path] if path.is_file() else sorted(path.rglob('*.log'))
    for file in files:
        with file.open('rb') as stream:
            for line in stream:
                values={k.decode():(a or b).decode('utf-8','replace') for k,a,b in KV.findall(line)}
                kind=values.get('type','unknown')+'/'+values.get('subtype','unknown')
                counts[kind]+=1
                if len(examples[kind])<3: examples[kind].append(line.decode('utf-8','replace').strip())
                if 'sentbyte' in values:
                    n=int(values['sentbyte'])
                    if len(sizes)<10000: sizes.append(n)
                    else:
                        j=rng.randrange(lines+1)
                        if j<10000: sizes[j]=n
                lines+=1
                if lines>=limit: break
        if lines>=limit: break
    sizes.sort()
    return dict(lines=lines,scope='prefix sample',types=dict(counts),sentbyte_sample_p999=sizes[int(.999*(len(sizes)-1))] if sizes else None,examples=dict(examples))


if __name__=='__main__':
    p=argparse.ArgumentParser(); p.add_argument('--path',default='/data');p.add_argument('--lines',type=int,default=200000)
    args=p.parse_args(); print(json.dumps(profile(Path(args.path),args.lines),indent=2))
