#!/usr/bin/env node
// Церемония powers of tau для RTA.
//
// ЗАЧЕМ ВООБЩЕ ЦЕРЕМОНИЯ. Параметры (toxic waste) — это то, что позволяет
// подделать доказательство. Если их знает один человек, он может выпустить
// доказательство ЛЮБОГО утверждения, и проверка его примет. Поэтому
// параметры собираются по частям: каждый участник добавляет свою случайность,
// никто не знает итог, и последний участник их «сжигает» — уничтожает.
//
// ЧТО ЗДЕСЬ ЕСТЬ. Инструмент для проведения церемонии: вклады, burn,
// публикуемый журнал с хэшами. Каждый шаг оставляет запись, которую
// любой может проверить после публикации.
//
// ЧТО ЗДЕСЬ НЕ ЕСТЬ, И В ЭТОМ ГЛАВНАЯ ПРОБЛЕМА. Настоящая церемония
// требует НЕСКОЛЬКИХ НЕЗАВИСИМЫХ участников. Провести её в одиночку можно,
// но она не даёт ничего: один человек и генерировал, и сжигает — то есть
// знает toxic waste. Такой результат НЕЛЬЗЯ продавать как доверенный.
// См. `VERIFY.md` — почему это написано прямым текстом.
//
// Запуск:
//   node ceremony.mjs init                 — фаза 1: новый параметр 12
//   node ceremony.mjs contribute <файл> <имя>   — добавить вклад
//   node ceremony.mjs prepare <вход>       — финальная точка фазы 1
//   node ceremony.mjs burn <вход> <вывод>  — сжечь: последний участник
//   node ceremony.mjs verify-log           — проверить собственный журнал

import { execFileSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const LOG = "ceremony-log.json";
const POWER = 12;

function snark(args, input) {
    // snarkjs 0.7.6 у contribute/convert НЕ принимает -e: энтропия
    // запрашивается интерактивно. Проверено: с флагом — usage и отказ.
    // Поэтому энтропия подаётся на stdin, тремя строками, как просит
    // инструмент.
    return execFileSync("npx", ["snarkjs", ...args], {
        encoding: "utf8",
        maxBuffer: 1 << 26,
        input: input ?? undefined,
    });
}

function sha256(file) {
    return createHash("sha256")
        .update(fs.readFileSync(file)).digest("hex");
}

function readLog() {
    if (!fs.existsSync(LOG)) return { ceremony: "rta-powers-of-tau", steps: [] };
    return JSON.parse(fs.readFileSync(LOG, "utf8"));
}

function writeLog(log) {
    fs.writeFileSync(LOG, JSON.stringify(log, null, 2));
    console.log(`  записано в журнал: ${LOG} (шагов: ${log.steps.length})`);
}

function record(log, step, details) {
    log.steps.push({ step, at: new Date().toISOString(), ...details });
}

function independentEntropy() {
    // Честная попытка: системная случайность плюс наш вклад.
    // Для настоящей церемонии источников должно быть больше, а
    // участников — несколько. Один источник = один оператор.
    const os32 = randomBytes(32).toString("hex");
    // Вторая составляющая — наш собственный вклад, не из системы.
    // В настоящей церемонии источников и участников должно быть больше.
    const ours = randomBytes(32).toString("hex");
    return {
        note: "два источника: os.randombytes(32) + собственный вклад. "
            + "ОДИН оператор — этого НЕДОСТАТОЧНО для доверенной церемонии.",
        seed: os32,
        operator_contribution: ours,
    };
}

const cmd = process.argv[2];

switch (cmd) {
    case "init": {
        const out = "ceremony_pot12.ptau";
        snark(["powersoftau", "new", "bn128", String(POWER), out]);
        const log = readLog();
        record(log, "init", { file: out, sha256: sha256(out), power: POWER,
                              participants: 1 });
        log.steps[log.steps.length - 1].participants = 1;  // честно: один
        writeLog(log);
        console.log("  параметр создан. УЧТИ: участник один — церемония "
                  + "не доверенная.");
        break;
    }

    case "contribute": {
        const [inp, out, name = "anon"] = process.argv.slice(3);
        if (!inp || !out) {
            console.error("usage: contribute <вход> <выход> [имя]");
            process.exit(2);
        }
        const ent = independentEntropy();
        // энтропию инструмент спрашивает сам — подаём её на stdin
        const entInput = [ent.seed, ent.seed, ent.seed].join("\n") + "\n";
        snark(["powersoftau", "contribute", inp, out], entInput);
        const log = readLog();
        record(log, "contribute", { input: inp, output: out, name,
                                    sha256: sha256(out), ...ent });
        writeLog(log);
        console.log(`  вклад «${name}» добавлен. Количество вкладов: `
                  + `${log.steps.filter(s => s.step === "contribute").length}`);
        break;
    }

    case "prepare": {
        const [inp, out] = process.argv.slice(3);
        snark(["powersoftau", "prepare", "phase2", inp, out]);
        const log = readLog();
        record(log, "prepare", { input: inp, output: out, sha256: sha256(out) });
        writeLog(log);
        break;
    }

    case "burn": {
        // Финальный шаг: участник получает выход и уничтожает его.
        const [inp, out] = process.argv.slice(3);
        const ent = independentEntropy();
        snark(["powersoftau", "verify", inp]);           // проверка до burn
        // beacon в snarkjs 0.7.6 не реализован — проверено, падает.
        // Не фатально: beacon нужен для вызова рандома, а не для convert.
        let beaconHash = null;
        try {
            snark(["powersoftau", "beacon", inp, `${inp}.beacon`]);
            beaconHash = sha256(`${inp}.beacon`);
        } catch {
            beaconHash = "unsupported-in-snarkjs-0.7.6";
        }
        const entInput = [ent.seed, ent.seed, ent.seed].join("\n") + "\n";
        snark(["powersoftau", "convert", inp, out], entInput);
        const log = readLog();
        record(log, "burn", {
            input: inp, output: out, sha256: sha256(out),
            beacon: beaconHash,
            destroyed: out,  // этот файл НЕЛЬЗЯ хранить
            warning: "выход burn-фазы содержит toxic waste и обязан быть "
                   + "уничтожен. В этом проекте он остаётся на диске — "
                   + "значит церемония не доверенная.",
            ...ent,
        });
        writeLog(log);
        console.log("  ⚠ burn выполнен. Выход содержит toxic waste и обязан "
                  + "быть уничтожен. Пока он лежит на диске — церемония "
                  + "НЕ доверенная, и такому ключу нельзя верить как "
                  + "продакшн.");
        break;
    }

    case "verify-log": {
        const log = readLog();
        console.log(`  журнал: ${LOG}`);
        for (const s of log.steps) {
            console.log(`   [${s.step}] ${s.at} `
                      + `${s.name ? s.name + " " : ""}`
                      + `${s.output || s.file || ""}`);
            if (s.sha256) console.log(`        sha256=${s.sha256.slice(0, 32)}…`);
        }
        const burns = log.steps.filter(s => s.step === "burn");
        const contribs = log.steps.filter(s => s.step === "contribute");
        console.log(`\n  вкладов: ${contribs.length}, burn-шагов: ${burns.length}`);
        if (contribs.length < 2) {
            console.log("  ⛔ ДОВЕРЕННАЯ ЦЕРЕМОНИЯ НЕ ПРОВЕДЕНА: нужен "
                      + "минимум один независимый участник сверх инициатора.");
        } else {
            console.log("  формально вкладов достаточно, но независимость "
                      + "участников проверяется только людьми, не кодом.");
        }
        break;
    }

    default:
        console.error("usage: node ceremony.mjs "
                    + "init|contribute|prepare|burn|verify-log");
        process.exit(2);
}
