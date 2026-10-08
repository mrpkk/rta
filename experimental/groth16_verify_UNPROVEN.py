"""⚠️ НЕ ДОВЕРЯТЬ. Файл вынесен из рабочего пути намеренно.

Причина: собственный верификатор Groth16 на py_ecc НЕ ПРОВЕРЕН.
Проверка на живой паре «доказательство + ключ» дала `уравнение не сошлось`,
а тест билинейности `e(aP,Q) == e(aQ,P)` не проходит. Значит перенос
формулы или соглашение о pairing неверны. Доказать, где именно, в этом
сеансе не удалось.

Почему это опаснее, чем отсутствие верификатора: сервер, который молча
отвергает верные доказательства или принимает неверные, хуже сервера без
проверки вообще. Для продукта доверия это недопустимо. Поэтому рабочий путь
использует snarkjs — он доказан верным по построению, своими же ключами.

Что всё же установлено вживую и полезно:
  · форматы точек snarkjs 0.7.6: [x,y], [x,y,"1"], {x,y}, {x,y,z:1}
  · бесконечность в py_ecc bn128 — это None (is_inf возвращает pt is None)
  · мои две первые догадки о бесконечности ((0,1) и ((1,0),(1,0))) неверны:
    обе не проходят is_on_curve

Если верификатор понадобится снова — начинать с тестов на БИЛИНЕЙНОСТЬ
и тождество, а не с рабочего доказательства.

Оригинальное описание:

Зачем свой код, если snarkjs уже умеет: **на этой машине Node-воркеры
зависают.** Память почти кончилась (14,2 из 15,5 ГБ занято), пул воркеров
ffjavascript не поднимается, и вызов `groth16.verify` висит 5 минут при
0,6 с процессорного времени — то есть процесс не считает, а ждёт.

Сервер не может зависеть от этого: проверка доказательства — его горячий
путь. Здесь нет ни потоков, ни внешних процессов, поэтому зависнуть нечему.

Формула перенесена из исходника snarkjs (`groth16Verify`), а не из
документации, и проверена на живом доказательстве из нашей же ключевой
пары — расхождение со snarkjs означал бы, что перенос неверен.

Само уравнение:
    e(-πa, πb) · e(cpub, γ) · e(πc, δ) == e(α, β)
где cpub = IC[0] + Σ publicSignals[i]·IC[i+1].
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from py_ecc.bn128 import (FQ, FQ2, G1, G2, add, b, b2, curve_order,
                          final_exponentiate, is_inf, is_on_curve, multiply,
                          neg, pairing)

# Точка на бесконечности в py_ecc bn128 — это None, что подтверждает
# is_inf() в исходнике пакета. Мои первые две догадки ((0,1) и ((1,0),(1,0)))
# оказались неверны: обе не проходят is_on_curve. Проверено пробой.
INFINITY = None


class VerifyError(ValueError):
    """Доказательство не разобрано или нарушено."""


def _fq2(obj: Any) -> FQ2:
    """Компонента FQ2: [c0, c1] либо один скаляр (c1 = 0)."""
    if isinstance(obj, (list, tuple)):
        if len(obj) == 1:
            return FQ2([FQ(int(obj[0])), FQ(0)])
        if len(obj) == 2:
            return FQ2([FQ(int(obj[0])), FQ(int(obj[1]))])
    return FQ2([FQ(int(obj)), FQ(0)])


def _g1(obj: Any) -> tuple:
    """Точка G1 -> (FQ x, FQ y).

    Встречаются четыре формы, все найдены на реальных файлах snarkjs 0.7.6:
        [x, y]                 - возвращается из API
        [x, y, "1"]            - проективная запись, третий элемент 1
        {"x": ..., "y": ...}   - аффинная в файле доказательства
        {"x": ..., "y": ..., "z": 1}
    Проективный элемент отбрасывается ТОЛЬКО если он равен 1. Иначе это
    другая точка, и молчаливое игнорирование стало бы дырой.
    """
    if isinstance(obj, dict):
        x, y = obj["x"], obj["y"]
        z = obj.get("z", 1)
    elif isinstance(obj, (list, tuple)) and len(obj) in (2, 3):
        x, y = obj[0], obj[1]
        z = obj[2] if len(obj) == 3 else 1
    else:
        raise VerifyError(f"G1: неожиданный формат {type(obj).__name__}")
    if str(z) != "1":
        raise VerifyError(f"G1: проективная координата {z!r} не равна 1 - "
                          f"точка не в аффинной форме")
    return (FQ(int(x)), FQ(int(y)))


def _g2(obj: Any) -> tuple:
    """Точка G2 -> пара FQ2 (x, y).

    Формы те же, что у G1; каждая компонента - пара FQ2, а весь пункт
    в проективной записи несёт третью пару ["1", "0"].
    """
    if isinstance(obj, dict):
        x, y = obj["x"], obj["y"]
        z = obj.get("z", [1, 0])
    elif isinstance(obj, (list, tuple)) and len(obj) in (2, 3):
        x, y = obj[0], obj[1]
        z = obj[2] if len(obj) == 3 else [1, 0]
    else:
        raise VerifyError(f"G2: неожиданный формат {type(obj).__name__}")
    if _fq2(z) != FQ2([FQ(1), FQ(0)]):
        raise VerifyError("G2: проективная координата не равна 1 - "
                          "точка не в аффинной форме")
    return (_fq2(x), _fq2(y))


def _is_on_curve_g1(p: tuple) -> bool:
    try:
        return is_inf(p) or is_on_curve(p, b)
    except Exception:
        return False


def _is_on_curve_g2(p: tuple) -> bool:
    try:
        return is_inf(p) or is_on_curve(p, b2)
    except Exception:
        return False


def _in_subgroup_g1(p: tuple) -> bool:
    return is_inf(multiply(p, curve_order))


def _in_subgroup_g2(p: tuple) -> bool:
    return is_inf(multiply(p, curve_order))


def load_verification_key(path: str | Path) -> dict:
    vk = json.loads(Path(path).read_text(encoding="utf-8"))
    if vk.get("protocol") != "groth16":
        raise VerifyError(f"протокол {vk.get('protocol')!r} не groth16")
    if vk.get("curve") not in (None, "bn128"):
        raise VerifyError(f"кривая {vk.get('curve')!r} не bn128 — код непригоден")
    return vk


def verify(vk: dict, proof: dict, public_signals: list | None = None) -> bool:
    """Проверить доказательство. True только при полном совпадении.

    Порядок проверок не случаен: сперва самые дешёвые отказы (форма,
    принадлежность подгруппам), потом единственная дорогая операция —
    pairing. Иначе каждая подделка стоила бы полной проверки.
    """
    if proof.get("protocol") != "groth16":
        return False
    signals = list(public_signals or [])

    ic = vk["IC"]
    if len(signals) + 1 != len(ic):
        # Несовпадение числа публичных входов и IC: доказательство от
        # другой схемы. Возвращать False, а не падать.
        return False

    try:
        pi_a, pi_b, pi_c = _g1(proof["pi_a"]), _g2(proof["pi_b"]), _g1(proof["pi_c"])
        alpha_1 = _g1(vk["vk_alpha_1"])
        beta_2 = _g2(vk["vk_beta_2"])
        gamma_2 = _g2(vk["vk_gamma_2"])
        delta_2 = _g2(vk["vk_delta_2"])
        ic_pts = [_g1(p) for p in ic]
    except (KeyError, TypeError, ValueError) as exc:
        raise VerifyError(f"доказательство или ключ не разобраны: {exc}") from exc

    for name, pt, chk in (("pi_a", pi_a, _is_on_curve_g1),
                          ("pi_c", pi_c, _is_on_curve_g1),
                          ("alpha", alpha_1, _is_on_curve_g1),
                          *[(f"IC[{i}]", p, _is_on_curve_g1)
                            for i, p in enumerate(ic_pts)]):
        if not chk(pt):
            raise VerifyError(f"{name} не находит на кривой")
    if not _is_on_curve_g2(pi_b):
        raise VerifyError("pi_b не находит на кривой G2")
    for name, pt in (("beta_2", beta_2), ("gamma_2", gamma_2),
                     ("delta_2", delta_2)):
        if not _is_on_curve_g2(pt):
            raise VerifyError(f"{name} не находит на кривой G2")

    if not _in_subgroup_g1(pi_a) or not _in_subgroup_g1(pi_c):
        return False
    if not _in_subgroup_g2(pi_b):
        return False

    # cpub = IC[0] + Σ signals[i]·IC[i+1]
    cpub = ic_pts[0]
    for i, s in enumerate(signals):
        cpub = add(cpub, multiply(ic_pts[i + 1], int(s)))

    try:
        lhs = (pairing(beta_2, neg(pi_a))
               * pairing(gamma_2, cpub)
               * pairing(delta_2, pi_c))
        rhs = pairing(beta_2, alpha_1)
    except Exception as exc:                 # крипто-ошибки не должны ронять сервис
        raise VerifyError(f"pairing не выполнен: {exc}") from exc

    return final_exponentiate(lhs) == final_exponentiate(rhs)


def verify_files(vk_path: str | Path, proof_path: str | Path,
                 public_path: str | Path) -> tuple[bool, str]:
    """Проверить по файлам. Возвращает (результат, причина/пояснение)."""
    try:
        vk = load_verification_key(vk_path)
        proof = json.loads(Path(proof_path).read_text(encoding="utf-8"))
        signals = json.loads(Path(public_path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return False, f"вход не разобран: {exc}"[:180]
    except VerifyError as exc:
        return False, str(exc)[:180]
    if not isinstance(signals, list):
        return False, "public.json должен быть массивом"
    if signals:
        return False, (f"публичные сигналы не пусты ({len(signals)}) — "
                       f"доказательство раскрывает данные")
    try:
        return verify(vk, proof, signals), "уравнение Groth16 сошлось"
    except VerifyError as exc:
        return False, str(exc)[:180]
