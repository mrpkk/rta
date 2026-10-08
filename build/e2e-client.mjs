// Клиентская сторона: построить доказательство и отдать его серверу.
// Скрипт существует ради сквозной проверки и как пример для покупателя.
import * as snarkjs from "snarkjs";
import fs from "node:fs";

const [zkey, wasm, vk, value, threshold, bits] = process.argv.slice(2);
const b = (v, n) => Array.from({ length: n }, (_, i) => (v >> BigInt(i)) & 1n).map(Number);

const secret = BigInt(value), thr = BigInt(threshold), n = Number(bits);
try {
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
        { secret: secret.toString(),
          secretBits: b(secret, n),
          diffBits: b(secret - thr, n) },
        wasm, zkey);
    fs.writeFileSync("proof.json", JSON.stringify(proof));
    fs.writeFileSync("public.json", JSON.stringify(publicSignals));
    console.log(`PROOF_OK public=${publicSignals.length} bytes=${JSON.stringify(proof).length}`);
} catch (e) {
    console.log("PROOF_IMPOSSIBLE " + String(e.message).slice(0, 90));
    process.exit(1);
}
