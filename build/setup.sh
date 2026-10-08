#!/usr/bin/env bash
# Полный цикл: компиляция схемы -> powers of tau -> groth16 setup -> ключи.
# Всё локально, без бюджета и без внешней церемонии.
# ВНИМАНИЕ: эта «церемония» годится только для локального стенда.
# Продакшн требует многосторонней церемонии с burn ceremony,
# иначе координатор церемонии может подделать доказательства.
set -euo pipefail
cd "$(dirname "$0")"
export PATH="$HOME/.cargo/bin:$PATH"

circom ../circuits/age.circom --r1cs --wasm --sym -o . -p ../circuits/age.circom
snarkjs powersoftau new bn128 12 pot12.ptau -v
snarkjs powersoftau contribute pot12.ptau pot12b.ptau --name="c1" -e="local only"
snarkjs powersoftau prepare phase2 pot12b.ptau pot12_final.ptau
snarkjs groth16 setup age.r1cs pot12_final.ptau age_final.zkey
snarkjs zkey contribute age_final.zkey age_final2.zkey --name="c2" -e="local only"
snarkjs zkey export verificationkey age_final2.zkey verification_key.json
echo "Готово: verification_key.json + age_final2.zkey"
