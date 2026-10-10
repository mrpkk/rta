import * as snarkjs from "snarkjs";
import fs from "fs";
const BASE = "/media/Sruti/iamthat/work/sales/rta";
const pred = process.argv[2];
const secret = parseInt(process.argv[3], 10);
const threshold = parseInt(process.argv[4], 10);
const bits = parseInt(process.argv[5], 10);
const bitsOf = (v, n) => Array.from({ length: n }, (_, i) => (v >> i) & 1);
const input = {
  secret: String(secret),          // схема ждёт три входа: secret + два массива бит
  secretBits: bitsOf(secret, bits),
  diffBits: bitsOf(secret - threshold, bits),
};
const { proof, publicSignals } = await snarkjs.groth16.fullProve(
  input,
  `${BASE}/circuits/generated/${pred}_js/${pred}.wasm`,
  `${BASE}/build/${pred}.zkey`);
fs.writeFileSync("/tmp/opencode/proof.json", JSON.stringify({ proof, publicSignals }));
console.log("  доказательство создано, публичных сигналов:", publicSignals.length);
