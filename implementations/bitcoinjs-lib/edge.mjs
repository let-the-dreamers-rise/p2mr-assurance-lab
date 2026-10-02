const BJS=process.env.BJS; if(!BJS){console.error('set BJS=/path/to/bitcoinjs-lib checkout (built)');process.exit(2);}
const { payments } = await import(BJS+'/src/esm/index.js');
const h=(x)=>Buffer.from(x,'hex');
const leaf=(i)=>({output:h('20'+i.toString(16).padStart(64,'0')+'ac'),version:0xc0});
const run=(name,f)=>{try{console.log(name,'->',f())}catch(e){console.log(name,'-> THROWS:',e.message)}};
// 1. depth-129 tree: left-deep chain
let t=leaf(0); for(let i=1;i<=129;i++) t=[t,leaf(i)];
run('depth129 witness cb length/32', ()=>{const p=payments.p2mr({scriptTree:t,redeem:{output:leaf(0).output,redeemVersion:0xc0}});return (p.witness[1].length-1)/32;});
run('depth129 validate built witness', ()=>{const p=payments.p2mr({scriptTree:t,redeem:{output:leaf(0).output,redeemVersion:0xc0}});payments.p2mr({output:p.output,witness:p.witness});return 'accepted';});
// 2. odd leaf version 0xc1
const t2=[{output:leaf(1).output,version:0xc1},leaf(2)];
run('odd version build', ()=>{const p=payments.p2mr({scriptTree:t2,redeem:{output:leaf(1).output,redeemVersion:0xc1}});return p.witness? 'built cb0='+p.witness[1][0].toString(16):'no witness';});
run('odd version self-validate', ()=>{const p=payments.p2mr({scriptTree:t2,redeem:{output:leaf(1).output,redeemVersion:0xc1}});payments.p2mr({output:p.output,witness:p.witness});return 'accepted';});
