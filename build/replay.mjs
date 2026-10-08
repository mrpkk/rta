// Защита от повторного предъявления доказательства.
//
// ПРОБЛЕМА. Доказательство в Groth16 — просто 723 байта. Оно не содержит
// ни возраста, ни времени, ни того, кому выдано. Поэтому одно и то же
// доказательство можно предъявлять проверяющему снова и снова, и каждый раз
// оно будет истинным. Если проверка стоит денег или даёт доступ —
// доказательство нужно сделать одноразовым.
//
// ЗДЕСЬ НЕТ НИКАКОЙ МАГИИ И ЭТО ВАЖНО. Защита от повтора — это НЕ часть
// ZK. Это подпись проверяющего и журнал выданных nonce. Доказательство
// остаётся нулевым знанием; защита живёт снаружи, на стороне того, кто
// выдаёт.
//
// ЧТО ЭТО НЕ РЕШАЕТ. Если проверяющий не проверяет nonce — защиты нет,
// сколько бы их ни было на стороне эмитента. Честная граница: механизм
// полезен ровно настолько, насколько проверяющий его соблюдает.

import { createHash, randomBytes } from "node:crypto";

// --------------------------------------------------------------- nonce

/** Случайный nonce: 32 байта из системного генератора. */
export function newNonce() {
    return randomBytes(32).toString("hex");
}

/** Идентификатор доказательства: хэш от самих байт доказательства. */
export function proofId(proof) {
    const bytes = typeof proof === "string"
        ? Buffer.from(proof, "utf8")
        : Buffer.from(JSON.stringify(proof));
    return "proof:" + createHash("sha256").update(bytes).digest("hex");
}

// ------------------------------------------------------------ журнал

/** Ошибка повтора — выдача не должна молча пройти второй раз. */
export class ReplayError extends Error {
    constructor(nonce) {
        super(`nonce ${nonce} уже предъявлен`);
        this.name = "ReplayError";
        this.nonce = nonce;
    }
}

export class NonceRegistry {
    /**
     * @param {{maxAgeMs?: number, now?: () => number}} [opts]
     *   maxAgeMs — сколько живёт неиспользованный nonce. Ноль и undefined
     *   означают «бессрочно», и это плохой выбор: старые nonce копятся.
     */
    constructor(opts = {}) {
        this.seen = new Map();          // nonce -> момент выдачи
        this.used = new Map();          // nonce -> момент предъявления
        this.maxAgeMs = opts.maxAgeMs ?? 0;
        this.now = opts.now ?? (() => Date.now());
    }

    /** Выдать nonce под предстоящее доказательство. */
    issue(nonce = newNonce()) {
        if (this.seen.has(nonce)) {
            throw new Error(`nonce ${nonce} уже выдан — повторная выдача `
                          + `заставила бы два клиента столкнуться на одном `
                          + `токене`);
        }
        this.seen.set(nonce, this.now());
        return nonce;
    }

    /**
     * Проверить и погасить nonce. Возвращает true, если nonce новый.
     * Бросает ReplayError при повторе — «принять и промолчать» здесь
     * означало бы ровно ту дыру, которую мы закрываем.
     */
    consume(nonce) {
        if (this.used.has(nonce)) {
            throw new ReplayError(nonce);
        }
        if (this.seen.has(nonce)) {
            this.used.set(nonce, this.now());
            return true;
        }
        // Незнакомый nonce: доказательство предъявлено без нашей выдачи.
        // Это тоже повтор или подделка — принимать нельзя.
        throw new ReplayError(nonce);
    }

    /** Статус nonce без гашения — для диагностики, не для проверки. */
    status(nonce) {
        if (this.used.has(nonce)) return "used";
        if (this.seen.has(nonce)) return "issued";
        return "unknown";
    }

    /** Сбросить просроченные неиспользованные nonce. */
    prune() {
        if (!this.maxAgeMs) return 0;
        const now = this.now();
        let n = 0;
        for (const [nonce, at] of this.seen) {
            if (!this.used.has(nonce) && now - at > this.maxAgeMs) {
                this.seen.delete(nonce);
                n++;
            }
        }
        return n;
    }

    stats() {
        return { issued: this.seen.size, used: this.used.size,
                 maxAgeMs: this.maxAgeMs };
    }
}

// --------------------------------------------------- связка с доказательством

/**
 * Проверить доказательство и погасить nonce одной операцией.
 * Порядок важен: nonce гасится ПОСЛЕ успешной проверки, иначе невалидное
 * доказательство сожжёт себе настоящий nonce.
 *
 * @param verifyFn  async (proof, nonce) => boolean — проверка ZK
 * @param registry  NonceRegistry
 */
export async function verifyOnce(proof, nonce, verifyFn, registry) {
    // Отказ ДО проверки: на «unknown» и «used» зрячно тратить цикл
    // верификации. Найдено тестом на повторе — повторное предъявление
    // доходило до snarkjs и там отваливалось само.
    const st = registry.status(nonce);
    if (st !== "issued") {
        throw new ReplayError(nonce);      // не выдан нами или уже сожжён
    }
    const ok = await verifyFn(proof, nonce);
    if (!ok) return false;                 // nonce остаётся живым
    registry.consume(nonce);               // гасим только после успеха
    return true;
}

/**
 * Связка proof_id + nonce: чтобы обезличить сам факт проверки в логах.
 * Хэш от пары необратим, но повторяемый — по нему видно, что это тот же
 * клиент с тем же токеном.
 */
export function requestId(proofIdValue, nonce) {
    return "req:" + createHash("sha256")
        .update(`${proofIdValue}|${nonce}`).digest("hex");
}
