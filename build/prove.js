// Проверка полного цикла Groth16: схема -> ключи -> доказательство -> проверка.
// Писано на API snarkjs, а не на CLI: CLI 0.7.6 пытается разобрать zkey
// как JSON и падает.
const snarkjs = require("snarkjs");
const fs = require("fs");

const bits = (v, n = 8) => Array.from({ length: n }, (_, i) => (v >> i) & 1);

async function prove(zkeyPath, wasmPath, age) {
    const input = {
        age: String(age),
        ageBits: bits(age),
        diffBits: bits(age - 18),
    };
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
        input, wasmPath, zkeyPath);
    const ok = await snarkjs.groth16.verify(
        JSON.parse(fs.readFileSync("verification_key.json", "utf8")),
        publicSignals, proof);
    return { age, ok, publicSignals };
}

(async () => {
    const zkey = "age_final2.zkey";
    const wasm = "age_js/age.wasm";

    for (const age of [17, 18, 21, 100]) {
        try {
            const r = await prove(zkey, wasm, age);
            console.log(`  возраст ${String(r.age).padStart(3)}  ` +
                        `проверка: ${r.ok ? "ПРИНЯТО" : "ОТКЛОНЕНО"}  ` +
                        `публично: [${r.publicSignals.join(", ")}]`);
        } catch (e) {
            // Для возраста < 18 witness-генератор обязан упасть:
            // ограничение невыполнимо, доказательства не существует.
            console.log(`  возраст ${String(age).padStart(3)}  ` +
                        `свидетельство не построилось — доказать нельзя ` +
                        `(${String(e.message).slice(0, 60)})`);
        }
    }
})();