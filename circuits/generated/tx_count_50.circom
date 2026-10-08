pragma circom 2.2.3;

// Доказывает: не меньше 50 операций — против одноразовых кошельков.
//
// Секрет раскладывается на 16 бит, разность (секрет - порог) — на те же
// 16 бит. Из равенства сумма(биты разности) = секрет - порог следует,
// что разность неотрицательна: отрицательное число в двоичной записи
// из неотрицательных бит не помещается.
//
// Что утекает: ничего. Публичные сигналы пусты. Размер доказательства
// определяется схемой, а не величиной секрета.
template ThresholdProof() {
    signal input secret;
    signal input secretBits[16];
    signal input diffBits[16];

    var accSecret = 0;
    var accDiff = 0;
    for (var i = 0; i < 16; i++) {
        secretBits[i] * (1 - secretBits[i]) === 0;
        accSecret += secretBits[i] * (1 << i);
        diffBits[i] * (1 - diffBits[i]) === 0;
        accDiff += diffBits[i] * (1 << i);
    }
    accSecret === secret;
    accSecret - 50 === accDiff;
}

component main = ThresholdProof();
