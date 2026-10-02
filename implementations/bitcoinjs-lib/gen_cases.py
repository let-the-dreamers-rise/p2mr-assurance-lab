import json, random, sys
import os
ROOT=os.path.join(os.path.dirname(os.path.abspath(__file__)),'..','..')
sys.path.insert(0,ROOT)
import p2mr
vec=json.load(open(os.path.join(ROOT,'vectors','p2mr_construction.json')))['test_vectors']
cases=[]
for t in vec:
    if 'scriptTree' not in t['given'] or 'internalPubkey' in t['given']: continue
    e=t['expected']
    cases.append({'id':t['id'],'tree':t['given']['scriptTree'],'spk':e['scriptPubKey'],'addr':e['bip350Address'],'cbs':e['scriptPathControlBlocks']})
rng=random.Random(360)
def rtree(d):
    if d==0 or rng.random()<0.3:
        n=rng.randint(1,60)
        v=rng.choice([0xc0,0xc0,0xc0,0xc2,0xfa])
        return {'script':bytes(rng.getrandbits(8) for _ in range(n)).hex(),'leafVersion':v}
    return [rtree(d-1),rtree(d-1)]
for i in range(2000):
    t=rtree(rng.randint(0,7))
    r=p2mr.construct_p2mr(t)
    cases.append({'id':f'rand{i}','tree':t,'spk':r['script_pubkey'].hex(),'addr':r['address'],'cbs':[c.hex() for c in r['control_blocks']]})
json.dump(cases,open(os.path.join(os.path.dirname(os.path.abspath(__file__)),'cases.json'),'w'))
print(len(cases))
