import json, hashlib, sys
import os
D=os.environ.get('QBIT_DATA') or sys.exit('set QBIT_DATA=/path/to/qbit/src/test/data/')
D=D.rstrip('/')+'/'
def th(tag,msg):
    t=hashlib.sha256(tag.encode()).digest(); return hashlib.sha256(t+t+msg).digest()
def cs(n):
    return bytes([n]) if n<0xfd else (b'\xfd'+n.to_bytes(2,'little') if n<=0xffff else b'\xfe'+n.to_bytes(4,'little'))
def leaf(v,s): return th('P2MRLeaf', bytes([v])+cs(len(s))+s)
def br(a,b): return th('P2MRBranch', a+b if a<b else b+a)
def verify(script, cb, root):
    if len(cb)<1 or len(cb)>1+32*128 or (len(cb)-1)%32: return 'WRONG_CONTROL_SIZE'
    if cb[0]&1!=1: return 'CONTROL_BIT0'
    k=leaf(cb[0]&0xfe, script)
    for i in range((len(cb)-1)//32): k=br(k, cb[1+32*i:33+32*i])
    return 'OK' if k==root else 'PROGRAM_MISMATCH'
d=json.load(open(D+'p2mr_vectors.json'))
ok=bad=0
for v in d['valid']:
    s=bytes.fromhex(v['leaf_script']); lh=leaf(v['leaf_version'],s)
    chk=[lh.hex()==v['leaf_hash']]
    k=lh
    for sib in v['siblings']: k=br(k,bytes.fromhex(sib))
    chk.append(k.hex()==v['merkle_root'])
    chk.append(('5220'+v['merkle_root'])==v['scriptPubKey'])
    chk.append(verify(s,bytes.fromhex(v['control_block']),bytes.fromhex(v['merkle_root']))=='OK')
    print('valid',v['id'],chk); ok+=all(chk); bad+= not all(chk)
for v in d['invalid']:
    r=verify(bytes.fromhex(v['leaf_script']),bytes.fromhex(v['control_block']),bytes.fromhex(v['merkle_root']))
    print('invalid',v['id'],'->',r,'| expected',v['expected_error'])
c=json.load(open(D+'p2mr_cross_profile_vectors.json'))
for v in c['vectors']:
    s=bytes.fromhex(v['leaf_script']); lv=int(v['leaf_version'],16) if isinstance(v['leaf_version'],str) else v['leaf_version']
    tl=th('TapLeaf',bytes([lv])+cs(len(s))+s).hex()
    print('cross',v['id'],'p2mrleaf ok' if leaf(lv,s).hex()==v['p2mr_leaf_root'] else 'p2mrleaf MISMATCH','| tapleaf ok' if tl==v['tapleaf_root'] else '| tapleaf MISMATCH')
print('valid agree',ok,'disagree',bad)
