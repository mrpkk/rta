// Проверяющая обёртка для сервиса.
//
// Отдельный процесс намеренно: snarkjs живёт на Node, сервис на Python.
// Слой «почти как настоящая проверка» на сервере означал бы, что настоящей
// проверки нет.
//
// Вход: proof.json, public.json, verification_key.json
// Выход: последняя строка — VERIFIED или REJECTED с причиной.

import fs from "node:fs";
import * as snarkjs from "snarkjs";

const [proofPath, publicPath, vkPath] = process.argv.slice(2);

if (!proofPath || !publicPath || !vkPath) {
    console.error("usage: verify-service.mjs proof.json public.json vk.json");
    process.exit(2);
}

function fail(why) {
    console.log(`REJECTED ${why}`);
    process.exit(1);
}

let proof, publicSignals, vk;
try {
    proof = JSON.parse(fs.readFileSync(proofPath, "utf8"));
    publicSignals = JSON.parse(fs.readFileSync(publicPath, "utf8"));
    vk = JSON.parse(fs.readFileSync(vkPath, "utf8"));
} catch (e) {
    fail(`вход не разобран: ${e.message.slice(0, 120)}`);
}

// Публичные сигналы обязаны быть пустыми: иначе клиент раскрыл секрет,
// и называть это «нулевым знанием» было бы враньём.
if (!Array.isArray(publicSignals)) {
    fail("public.json должен быть массивом");
}
if (publicSignals.length !== 0) {
    fail(`ожидались пустые публичные сигналы, получено ${publicSignals.length}`
         + ` — доказательство раскрывает данные`);
}

if (!proof || typeof proof !== "object" || !proof.protocol) {
    fail("в proof.json нет протокола доказательства");
}

try {
    const ok = await snarkjs.groth16.verify(vk, publicSignals, proof);
    console.log(ok ? "VERIFIED" : "REJECTED проверка Groth16 не сошлась");
    process.exit(ok ? 0 : 1);
} catch (e) {
    fail(`ошибка проверки: ${String(e.message).slice(0, 140)}`);
}
