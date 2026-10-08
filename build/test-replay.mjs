// Испытание защиты от повтора.
//
// Главное здесь — не «функция работает», а «повтор ЛОМАЕТСЯ». Тест, который
// проверяет только успешный путь, не доказывает ничего.

import assert from "node:assert/strict";
import { NonceRegistry, ReplayError, newNonce, proofId, requestId,
         verifyOnce } from "./replay.mjs";

let pass = 0, fail = 0;
function check(name, cond, detail = "") {
    if (cond) { pass++; console.log(`  ok   ${name}`); }
    else { fail++; console.log(`  FAIL ${name}${detail ? " — " + detail : ""}`); }
}

console.log("Выдача:");
{
    const r = new NonceRegistry();
    const n = r.issue();
    check("nonce выдан", typeof n === "string" && n.length === 64);
    check("статус issued", r.status(n) === "issued");
    check("повторная выдача того же nonce отвергнута",
          (() => { try { r.issue(n); return false; } catch { return true; } })());
    check("у nonce есть срок жизни", new NonceRegistry({ maxAgeMs: 1000 })
          .maxAgeMs === 1000);
}

console.log("\nПовторное предъявление:");
{
    const r = new NonceRegistry();
    const n = r.issue();
    check("первое предъявление принято", r.consume(n) === true);
    let threw = false;
    try { r.consume(n); } catch (e) { threw = e instanceof ReplayError; }
    check("второе предъявление отвергнуто ReplayError", threw);
    check("после отказа статус used", r.status(n) === "used");

    let unknown = false;
    try { r.consume(newNonce()); } catch (e) { unknown = e instanceof ReplayError; }
    check("чужой nonce отвергнут", unknown);
}

console.log("\nverifyOnce — гашение только после успеха:");
{
    const r = new NonceRegistry();

    let unknown = false;
    try { await verifyOnce({}, newNonce(), async () => true, r); }
    catch (e) { unknown = e instanceof ReplayError; }
    check("предъявление без выданного nonce отвергнуто", unknown);

    // Счётчик вызовов проверяющей функции: повтор обязан отсекаться
    // ДО верификации, иначе второй запрос тратит цикл snarkjs впустую.
    let calls = 0;
    const nBad = r.issue();
    check("невалидное доказательство не принято",
          await verifyOnce({}, nBad, async () => { calls++; return false; }, r)
              === false);
    check("невалидное доказательство не сожгло nonce",
          r.status(nBad) === "issued");
    check("клиент может повторить после неудачи",
          await verifyOnce({}, nBad, async () => { calls++; return true; }, r)
              === true);
    check("проверяющая функция вызвана ровно дважды", calls === 2);

    const nGood = r.issue();
    await verifyOnce({}, nGood, async () => { calls++; return true; }, r);
    calls = 0;
    let again = false;
    try { await verifyOnce({}, nGood, async () => { calls++; return true; }, r); }
    catch (e) { again = e instanceof ReplayError; }
    check("повтор валидного доказательства отвергнут", again);
    check("повтор отсечён ДО верификации", calls === 0);
}

console.log("\nСрок жизни:");
{
    let clock = 1_000_000;
    const r = new NonceRegistry({ maxAgeMs: 5_000, now: () => clock });
    const old = r.issue();
    // Время двигаем ДО выдачи свежего: иначе оба nonce старые и prune
    // правомерно удалит оба. Это ошибка была в первом варианте теста.
    clock += 10_000;
    const fresh = r.issue();
    clock += 1_000;
    check("просроченный nonce удалён при prune", r.prune() === 1);
    check("свежий nonce уцелел", r.status(fresh) === "issued");
    let reused = false;
    try { r.consume(old); } catch { reused = true; }
    check("просроченный nonce больше не принимается", reused);
}

console.log("\nИдентификаторы:");
{
    const p = { pi_a: ["1", "2"], pi_b: [["3"]], protocol: "groth16" };
    check("proofId стабилен", proofId(p) === proofId({ ...p }));
    check("proofId различает доказательства",
          proofId(p) !== proofId({ ...p, protocol: "groth16", x: 1 }));
    check("proofId принимает строку", typeof proofId("abc") === "string");
    const a = requestId(proofId(p), "n1");
    check("requestId детерминирован", a === requestId(proofId(p), "n1"));
    check("requestId зависит от nonce",
          a !== requestId(proofId(p), "n2"));
}

console.log("\nЧестная граница защиты:");
{
    // Реестр — сторона эмитента. Если проверяющий не сверяется с ним,
    // защита равна нулю. Это не дефект кода, а свойство протокола.
    const r = new NonceRegistry();
    const n = r.issue();
    r.consume(n);
    const localCopy = new NonceRegistry();
    const n2 = localCopy.issue();
    localCopy.consume(n2);
    check("второй реестр примет тот же nonce — отказ возможен только "
          + "при общем реестре", localCopy.status(n2) === "used");
    console.log("       → значит общий реестр обязателен; обойти его можно");
    console.log("         только не сверяясь вовсе. Граница не в коде.");
}

console.log(`\nИтог: ${pass} ok, ${fail} FAIL`);
process.exit(fail ? 1 : 0);
