// Генератор схем «докажи порог, не раскрывая число».
//
// Почему генератор, а не пачка файлов: порог — это параметр, а не суть
// схемы. Суть одна — доказательство, что секретное число не меньше
// заданного порога, причём само число не раскрывается. Переписывать схему
// под каждый порог руками означает размножить копии, которые разъедутся.
//
// Из чего собирается шаблон:
//   bits        — разрядность секрета (8 -> 0..255, 32 -> до ~4,3 млрд)
//   threshold   — порог, публикуется
//   bitsOfThr   — разрядность самого порога, чтобы он помещался
//
// Ограничение, которое нельзя обойти: разрядность порога не может
// превышать разрядность секрета, иначе порог недостижим и доказательство
// невозможно — это схема будет врёт своим именем.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const OUT = path.join(HERE, "..", "circuits", "generated");

const TPL = (name, comment, bits, threshold) => `pragma circom 2.2.3;

// ${comment}
//
// Секрет раскладывается на ${bits} бит, разность (секрет - порог) — на те же
// ${bits} бит. Из равенства сумма(биты разности) = секрет - порог следует,
// что разность неотрицательна: отрицательное число в двоичной записи
// из неотрицательных бит не помещается.
//
// Что утекает: ничего. Публичные сигналы пусты. Размер доказательства
// определяется схемой, а не величиной секрета.
template ThresholdProof() {
    signal input secret;
    signal input secretBits[${bits}];
    signal input diffBits[${bits}];

    var accSecret = 0;
    var accDiff = 0;
    for (var i = 0; i < ${bits}; i++) {
        secretBits[i] * (1 - secretBits[i]) === 0;
        accSecret += secretBits[i] * (1 << i);
        diffBits[i] * (1 - diffBits[i]) === 0;
        accDiff += diffBits[i] * (1 << i);
    }
    accSecret === secret;
    accSecret - ${threshold} === accDiff;
}

component main = ThresholdProof();
`;

export function generate() {
    fs.mkdirSync(OUT, { recursive: true });

    const variants = [
        { file: "balance_1000.circom", bits: 32, threshold: 1000,
          comment: "Доказывает: баланс >= 1000, не раскрывая баланс." },
        { file: "balance_100000.circom", bits: 48, threshold: 100000,
          comment: "Доказывает: баланс >= 100000 (USDC), не раскрывая сумму." },
        { file: "account_age_180.circom", bits: 16, threshold: 180,
          comment: "Доказывает: возраст аккаунта >= 180 дней — против "
                 + "свежесозданных кошельков." },
        { file: "tx_count_50.circom", bits: 16, threshold: 50,
          comment: "Доказывает: не меньше 50 операций — против "
                 + "одноразовых кошельков." },
        { file: "stake_10000.circom", bits: 32, threshold: 10000,
          comment: "Доказывает: залог >= 10000, не раскрывая сумму залога." },
    ];

    const written = [];
    for (const v of variants) {
        const dest = path.join(OUT, v.file);
        fs.writeFileSync(dest, TPL(v.file, v.comment, v.bits, v.threshold));
        written.push({ file: v.file, bits: v.bits, threshold: v.threshold });
    }

    // Отвергнуто с причинами — чтобы не предлагали заново.
    const rejected = `# Не сделано и почему

## Санкционный статус — криптографически сложно, не сделано

Заявка «мой санкционный статус чист» означает **непринадлежность** множеству.
Нужен zero-knowledge proof of NON-membership.

- Доказательство **принадлежности** через Merkle-путь делается легко, но
  оно раскрывает, КАКОЙ именно элемент предъявлен. Для санкций это
  раскрывает ровно то, что нужно скрыть.
- Доказательство непринадлежности требует аргумента о непринадлежности
  (zero-knowledge lookup) — это тяжёлая машинерия с доменом на миллионы
  ограничений.
- Обходной путь «признать элемент списка» раскрывает страну, а это
  противоречит обещанию продукта.

**Вывод: не делаем в виде «докажи, что тебя нет в списке».** Если понадобится
— делаем честно через membership в белом списке (доказываем, что страна
ЕСТЬ в списке безопасных), и это отдельная схема с отдельными последствиями.

## Отрицание порога («менее 1000») — не сделано

Схема доказывает «не меньше». Отрицание требует другого предиката.
Возможно технически, но покупатель для «баланс < 1000» не найден.

## Точность даты — не сделано

Есть «возраст аккаунта >= 180 дней», нет «создан 12 марта 2024».
Точная дата требует сравнения по сложному модулю, а не по разрядности.
`;

    fs.writeFileSync(path.join(OUT, "ОТВЕРГНУТО.md"), rejected);
    return written;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
    const w = generate();
    console.log(`  схем сгенерировано: ${w.length}`);
    for (const x of w) {
        console.log(`   ${x.file}  ${x.bits} бит, порог ${x.threshold}`);
    }
}
