import * as snarkjs from "snarkjs";
import fs from "node:fs";
const bits=(v,n)=>Array.from({length:n},(_,i)=>(v>>BigInt(i))&1n).map(Number);
const cases=[['balance_1000',32,1000,5000],['balance_100000',48,100000,250000],
             ['account_age_180',16,180,400],['tx_count_50',16,50,900],
             ['stake_10000',32,10000,50000]];
let ok=0,bad=0;
for(const [name,b,thr,val] of cases){
  const vk=JSON.parse(fs.readFileSync(name+'_vk.json','utf8'));
  const v=BigInt(val);
  const {proof,publicSignals}=await snarkjs.groth16.fullProve(
    {secret:v.toString(),secretBits:bits(v,b),diffBits:bits(v-BigInt(thr),b)},
    '../circuits/generated/'+name+'_js/'+name+'.wasm', name+'.zkey');
  const good=await snarkjs.groth16.verify(vk,publicSignals,proof);
  const forged=await snarkjs.groth16.verify(vk,['999999'],proof).catch(()=>false);
  if(good&&!forged) ok++; else bad++;
  console.log('  '+name.padEnd(18),'проверка:',good?'ПРИНЯТО':'ОТКЛОНЕНО',
              '| подделка:',forged?'ПРОШЛА (ПЛОХО)':'отвергнута');
}
console.log('\nИтог:',ok,'схем верны,',bad,'с проблемой');
