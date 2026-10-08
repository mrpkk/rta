pragma circom 2.2.3;

// Доказывает: баланс >= 100000 (USDC), не раскрывая сумму.
//
// Секрет раскладывается на 48 бит, разность (секрет - порог) — на те же
// 48 бит. Из равенства сумма(биты разности) = секрет - порог следует,
// что разность неотрицательна: отрицательное число в двоичной записи
// из неотрицательных бит не помещается.
//
// Что утекает: ничего. Публичные сигналы пусты. Размер доказательства
// определяется схемой, а не величиной секрета.
template ThresholdProof() {
    signal input secret;
    signal input secretBits[48];
    signal input diffBits[48];

    var accSecret = 0;
    var accDiff = 0;
    for (var i = 0; i < 48; i++) {
        secretBits[i] * (1 - secretBits[i]) === 0;
        accSecret += secretBits[i] * (1 << i);
        diffBits[i] * (1 - diffBits[i]) === 0;
        accDiff += diffBits[i] * (1 << i);
    }
    accSecret === secret;
    accSecret - 100000 === accDiff;
}

component main = ThresholdProof();
