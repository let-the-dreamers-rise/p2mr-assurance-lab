import fs from 'fs';
const BJS=process.env.BJS; if(!BJS){console.error('set BJS=/path/to/bitcoinjs-lib checkout (built)');process.exit(2);}
const { payments } = await import(BJS+'/src/esm/index.js');
const h=(x)=>Buffer.from(x,'hex'); const hx=(u)=>Buffer.from(u).toString('hex');
function conv(n){ if(Array.isArray(n)) return [conv(n[0]),conv(n[1])]; return {output:h(n.script), version:n.leafVersion??0xc0}; }
function leaves(n,acc=[]){ if(Array.isArray(n)){leaves(n[0],acc);leaves(n[1],acc);} else acc.push(n); return acc; }
const cases=JSON.parse(fs.readFileSync(new URL('./cases.json', import.meta.url)));
let ok=0, fail=[];
for(const c of cases){
  try{
    const tree=conv(c.tree);
    const p=payments.p2mr({scriptTree:tree});
    const errs=[];
    if(hx(p.output)!==c.spk) errs.push('spk');
    if(p.address!==c.addr) errs.push('addr');
    leaves(c.tree).forEach((l,i)=>{
      const q=payments.p2mr({scriptTree:tree, redeem:{output:h(l.script), redeemVersion:l.leafVersion??0xc0}});
      const cb=hx(q.witness[q.witness.length-1]);
      if(cb!==c.cbs[i]) errs.push(`cb${i}`);
      // round-trip: validate spend witness against output
      payments.p2mr({output:p.output, witness:[h(l.script), h(c.cbs[i])]});
    });
    if(errs.length) fail.push([c.id,errs.join(',')]); else ok++;
  }catch(e){ fail.push([c.id,'THROW '+e.message]); }
}
console.log('agree',ok,'of',cases.length); console.log(JSON.stringify(fail.slice(0,15)));
const kinds={}; for(const [id,e] of fail){const k=e.replace(/\d+/g,'');kinds[k]=(kinds[k]||0)+1}; console.log(kinds);
