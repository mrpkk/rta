// Испытание всех пороговых предикатов.
//
// Для каждой схемы проверяется одно и то же: число выше порога —
// доказательство принимается; число ниже — доказать НЕЛЬЗЯ; публичные
// сигналы пусты. Если хоть одна схема ведёт себя иначе — она негодна,
// даже если остальные в порядке.

import assert from "node:assert/strict";

import path from "node:path";
import { fileURLToPath } from "node:url";
import * as snarkjs from "snarkjs";
import { NonceRegistry, verifyOnce } from "./replay.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const GEN = path.join(HERE, "..", "circuits", "generated");

const bits = (v, n) => Array.from({ length: n }, (_, i) => (v >> BigInt(i)) & 1n)
    .map(Number);

const CASES = [
    { name: "balance_1000",   bits: 32, threshold: 1000,
      above: [1000, 1001, 50000, 4000000000],
      below: [0, 1, 999] },
    { name: "balance_100000", bits: 48, threshold: 100000,
      above: [100000, 250000], below: [0, 99999] },
    { name: "account_age_180", bits: 16, threshold: 180,
      above: [180, 181, 2000, 65535], below: [0, 1, 179] },
    { name: "tx_count_50",    bits: 16, threshold: 50,
      above: [50, 51, 900], below: [0, 1, 49] },
    { name: "stake_10000",    bits: 32, threshold: 10000,
      above: [10000, 10001, 999999], below: [0, 9999] },
];

let pass = 0, fail = 0;
function check(name, cond, detail = "") {
    if (cond) { pass++; console.log(`  ok   ${name}`); }
    else { fail++; console.log(`  FAIL ${name}${detail ? " — " + detail : ""}`); }
}

async function tryProve(c, value) {
    const zkey = path.join(HERE, `${c.name}.zkey`);
    const wasm = path.join(GEN, `${c.name}_js`, `${c.name}.wasm`);
    const v = BigInt(value);
    try {
        const { proof, publicSignals } = await snarkjs.groth16.fullProve(
            { secret: v.toString(),
              secretBits: bits(v, c.bits),
              diffBits: bits(v - BigInt(c.threshold), c.bits) },
            wasm, zkey);
        return { made: true, publicSignals, proof };
    } catch {
        return { made: false };
    }
}

for (const c of CASES) {
    console.log(`\n${c.name} (порог ${c.threshold}, ${c.bits} бит):`);

    for (const v of c.above) {
        const r = await tryProve(c, v);
        check(`  ${v} >= ${c.threshold}: доказательство построено`, r.made);
        if (r.made) {
            check(`  публичные сигналы пусты — число не раскрыто`,
                  r.publicSignals.length === 0,
                  JSON.stringify(r.publicSignals));
        }
    }

    for (const v of c.below) {
        const r = await tryProve(c, v);
        check(`  ${v} < ${c.threshold}: доказать нельзя`, !r.made,
              r.made ? "свидетельство построилось!" : "");
    }
}

console.log("\nПорог недостижим — доказательство невозможно:");
{
    // Значение шире разрядности схемы: 16 бит не вместят 70000.
    const r = await tryProve(CASES[2], 70000);
    check("число шире разрядности схемы отвергнуто", !r.made);
}

console.log("\nОпровержимость — главное свойство:");
{
    const c = CASES[3];               // tx_count_50
    const good = await tryProve(c, 500);
    check("истинное утверждение доказуемо", good.made);
    const lie = await tryProve(c, 10);
    check("ложное утверждение недоказуемо", !lie.made);

    // И защита от повтора поверх: одно и то же — один раз.
    const reg = new NonceRegistry();
    const nonce = reg.issue();
    let accepted = 0;
    for (let i = 0; i < 3; i++) {
        try {
            await verifyOnce({}, nonce, async () => true, reg);
            accepted++;
        } catch { /* отказ — ожидаем */ }
    }
    check("доказательство принято ровно один раз", accepted === 1,
          `принято ${accepted}`);
}

console.log(`\nИтог: ${pass} ok, ${fail} FAIL`);
process.exit(fail ? 1 : 0);
