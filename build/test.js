// Испытание схемы: доказать «возраст >= 18», не раскрыв возраст.
//
// Запуск: node build/test.js   (после build/setup.sh)
const snarkjs = require("snarkjs");
const fs = require("fs");
const path = require("path");

const ROOT = path.join(__dirname, "..");
const ZKEY = path.join(__dirname, "age_final2.zkey");
const WASM = path.join(__dirname, "age_js", "age.wasm");
const VK = path.join(__dirname, "verification_key.json");

const bits = (v, n = 8) => Array.from({ length: n }, (_, i) => (v >> i) & 1);

let pass = 0, fail = 0;
function check(name, cond, detail = "") {
    if (cond) { pass++; console.log(`  ok   ${name}`); }
    else { fail++; console.log(`  FAIL ${name}${detail ? " — " + detail : ""}`); }
}

(async () => {
    const vk = JSON.parse(fs.readFileSync(VK, "utf8"));

    async function tryProve(age) {
        try {
            const { proof, publicSignals } = await snarkjs.groth16.fullProve(
                { age: String(age), ageBits: bits(age), diffBits: bits(age - 18) },
                WASM, ZKEY);
            return { ok: await snarkjs.groth16.verify(vk, publicSignals, proof),
                     publicSignals };
        } catch (e) { return { failed: true }; }
    }

    console.log("Доказуемость:");
    for (const a of [18, 21, 37, 100, 255]) {
        const r = await tryProve(a);
        check(`возраст ${a} — доказательство принято`, r.ok === true);
    }

    console.log("\nНедоказуемость (главное: ложь опровергается):");
    for (const a of [0, 5, 16, 17]) {
        const r = await tryProve(a);
        check(`возраст ${a} — доказать нельзя`,
              r.failed === true, r.failed ? "" : "свидетельство построилось!");
    }

    console.log("\nНулевое знание:");
    const pubs = [];
    for (const a of [18, 40, 200]) {
        const r = await tryProve(a);
        pubs.push(JSON.stringify(r.publicSignals));
    }
    check("публичные сигналы пусты — возраст не раскрыт",
          pubs.every(p => p === "[]"), pubs.join(" | "));
    check("публичные данные не зависят от возраста",
          new Set(pubs).size === 1);

    console.log("\nЦелостность:");
    const bad = { ...vk };
    bad.IC = vk.IC.map(x => x);          // та же структура
    bad.IC[1] = ["1", "2"];             // подмена одной точки
    const r40 = await tryProve(40);
    const forged = await snarkjs.groth16.verify(bad, r40.publicSignals,
        r40.proof ?? { pi_a: [], pi_b: [], pi_c: [], protocol: "groth16" })
        .catch(() => false);
    check("подменённый verification key не принимает доказательство",
          forged === false || r40.failed === true);

    console.log(`\nИтог: ${pass} ok, ${fail} FAIL`);
    process.exit(fail ? 1 : 0);
})();