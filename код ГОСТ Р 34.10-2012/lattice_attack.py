"""
Восстановление секретного ключа ГОСТ Р 34.10-2012 по частичной утечке
старших бит нонсов (Hidden Number Problem) — вариант CVP (ближайший вектор).

Подход (по выкладке "центр + полуширина", с приведением по q):
  Подпись:  s = r*d + k*e (mod q)  =>  d = (s - k*e)*r^{-1}.
  Известны старшие L бит нонса k_i (a_i), значит d*A_i mod q близко к t_i, где
      A_i = -e_i^{-1} r_i mod q,   U_i = e_i^{-1} s_i mod q,   t_i = (a_i - U_i) mod q.
  Строим решётку (размерность m+1) и целевой вектор u=(t_1,...,t_m,0);
  ближайший к u вектор решётки содержит d. Ищем его алгоритмом Бабая
  (nearest plane) на LLL-приведённом базисе.

ВАЖНО: модуль всей арифметики — порядок подгруппы q (НЕ модуль поля p!).

Вход: публичный датасет из gost.py (dataset_public_*.txt).
Проверка успеха — по открытому ключу: d*G == Y.

Запуск:  python lattice_attack.py [dataset_public_XXXX.txt]
"""

import glob
import os
import random
import re
import sys
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from fractions import Fraction

import gost

# Быстрый решатель CVP через fpylll (C-библиотека). Если не установлен —
# откатываемся на чистый Python (lll_int + babai_nearest_plane).
try:
    from fpylll import (IntegerMatrix, LLL as _FP_LLL, BKZ as _FP_BKZ,
                        CVP as _FP_CVP, FPLLL as _FPLLL)
    _HAVE_FPYLLL = True
except Exception:
    _HAVE_FPYLLL = False

# Блок BKZ (0 = только LLL). Усиливает редукцию для малого числа бит утечки,
# но заметно медленнее. Ставьте 20-40 для трудных случаев.
BKZ_BLOCK = 0
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass


# ------------------------------------------------------------------ #
#  Разбор датасета                                                     #
# ------------------------------------------------------------------ #
def load_public(path):
    text = open(path, encoding="utf-8").read()
    q = int(re.search(r"q = ([01]+)", text).group(1), 2)
    Yx = int(re.search(r"Yx = ([01]+)", text).group(1), 2)
    Yy = int(re.search(r"Yy = ([01]+)", text).group(1), 2)
    L = int(re.search(r"leak_bits = (\d+)", text).group(1))

    sigs = {}
    for n, rs in re.findall(r"S(\d+) = \(([01]+, [01]+)\)", text):
        r_s, s_s = rs.split(", ")
        sigs.setdefault(int(n), {}).update(r=int(r_s, 2), s=int(s_s, 2))
    for n, v in re.findall(r"e(\d+) = ([01]+)", text):
        sigs[int(n)]["e"] = int(v, 2)
    for n, v in re.findall(r"leak(\d+) = ([01]+)", text):
        sigs[int(n)]["leak"] = int(v, 2)

    return q, (Yx, Yy), L, [sigs[i] for i in sorted(sigs)]


def pick_curve(q):
    for fn in (gost.id_tc26_gost_3410_12_512_paramSetA,
               gost.id_tc26_gost_3410_12_512_paramSetB):
        p, a, b, m, qq, G = fn()
        if qq == q:
            return p, a, b, G
    raise ValueError("q не совпал ни с одним известным набором параметров")


# ------------------------------------------------------------------ #
#  Целочисленный LLL (Cohen 2.6.7) — приведение базиса перед Бабаем    #
# ------------------------------------------------------------------ #
def lll_int(basis, delta_num=99, delta_den=100):
    nv = len(basis)
    dim = len(basis[0])
    b = [None] + [list(map(int, row)) for row in basis]
    d = [0] * (nv + 1)
    d[0] = 1
    lam = [[0] * (nv + 1) for _ in range(nv + 1)]

    def dot(u, v):
        return sum(x * y for x, y in zip(u, v))

    def RED(k, l):
        if 2 * abs(lam[k][l]) <= d[l]:
            return
        qq = (2 * lam[k][l] + d[l]) // (2 * d[l])
        b[k] = [b[k][t] - qq * b[l][t] for t in range(dim)]
        lam[k][l] -= qq * d[l]
        for i in range(1, l):
            lam[k][i] -= qq * lam[l][i]

    def SWAP(k, kmax):
        b[k], b[k - 1] = b[k - 1], b[k]
        for j in range(1, k - 1):
            lam[k][j], lam[k - 1][j] = lam[k - 1][j], lam[k][j]
        lm = lam[k][k - 1]
        Bn = (d[k - 2] * d[k] + lm * lm) // d[k - 1]
        for i in range(k + 1, kmax + 1):
            t = lam[i][k]
            lam[i][k] = (d[k] * lam[i][k - 1] - lm * t) // d[k - 1]
            lam[i][k - 1] = (Bn * t + lm * lam[i][k]) // d[k]
        d[k - 1] = Bn

    kmax = 1
    d[1] = dot(b[1], b[1])
    k = 2
    while k <= nv:
        if k > kmax:
            kmax = k
            for j in range(1, k + 1):
                u = dot(b[k], b[j])
                for i in range(1, j):
                    u = (d[i] * u - lam[k][i] * lam[j][i]) // d[i - 1]
                if j < k:
                    lam[k][j] = u
                else:
                    d[k] = u
        while True:
            RED(k, k - 1)
            if delta_den * d[k] * d[k - 2] < \
               delta_num * d[k - 1] * d[k - 1] - delta_den * lam[k][k - 1] ** 2:
                SWAP(k, kmax)
                k = max(2, k - 1)
            else:
                for l in range(k - 2, 0, -1):
                    RED(k, l)
                k += 1
                break
    return [b[i] for i in range(1, nv + 1)]


# ------------------------------------------------------------------ #
#  Ортогонализация Грама–Шмидта и алгоритм Бабая (nearest plane)       #
# ------------------------------------------------------------------ #
def _gram_schmidt(basis):
    dim = len(basis[0])
    Bstar, norms = [], []
    for row in basis:
        v = [Fraction(x) for x in row]
        for bs, nrm in zip(Bstar, norms):
            mu = sum(Fraction(row[k]) * bs[k] for k in range(dim)) / nrm
            v = [v[k] - mu * bs[k] for k in range(dim)]
        Bstar.append(v)
        norms.append(sum(x * x for x in v))
    return Bstar, norms


def babai_nearest_plane(basis, target):
    """Ближайший вектор решётки (базис уже LLL-приведён) к target."""
    dim = len(target)
    Bstar, norms = _gram_schmidt(basis)
    b = [Fraction(x) for x in target]
    for i in range(len(basis) - 1, -1, -1):
        c = round(sum(b[k] * Bstar[i][k] for k in range(dim)) / norms[i])
        b = [b[k] - c * basis[i][k] for k in range(dim)]
    # closest = target - остаток
    return [int(target[k] - b[k]) for k in range(dim)]


def _solve_cvp(basis, target):
    """Ближайший вектор решётки к target.
    fpylll: для больших чисел (>200 бит) — mpfr/heuristic (дефолтный wrapper на них
    зависает, т.к. в сборке нет qd); для малых — быстрый дефолт. Иначе чистый Python."""
    if _HAVE_FPYLLL:
        M = IntegerMatrix.from_matrix([list(map(int, row)) for row in basis])
        maxbits = max(abs(x) for row in basis for x in row).bit_length()
        if maxbits > 200:
            _FPLLL.set_precision(maxbits)
            _FP_LLL.reduction(M, method="heuristic", float_type="mpfr")
            if BKZ_BLOCK >= 2:
                _FP_BKZ.reduction(M, _FP_BKZ.Param(block_size=min(len(basis), BKZ_BLOCK),
                                                   float_type="mpfr"))
        else:
            _FP_LLL.reduction(M)
            if BKZ_BLOCK >= 2:
                _FP_BKZ.reduction(M, _FP_BKZ.Param(block_size=min(len(basis), BKZ_BLOCK)))
        return list(_FP_CVP.closest_vector(M, tuple(int(x) for x in target)))
    reduced = lll_int(basis)
    return babai_nearest_plane(reduced, target)


# ------------------------------------------------------------------ #
#  Восстановление ключа (CVP)                                          #
# ------------------------------------------------------------------ #
def recover_key(data, q, L, p, a, G, Y):
    m = q.bit_length()
    B = 1 << (m - L)                 # разброс неизвестной младшей части нонса
    half = B >> 1                    # рецентрирование: ошибка -> [-B/2, B/2)
    ksc = max(1, q // B)             # балансировка веса d против ошибки (~2^L)

    A, t = [], []
    for s in data:
        e_inv = pow(s["e"], -1, q)
        A.append((-e_inv * s["r"]) % q)                 # A_i = -e_i^{-1} r_i
        U_i = (e_inv * s["s"]) % q                       # U_i = e_i^{-1} s_i
        a_i = s["leak"] << (m - L)                       # известные старшие биты нонса
        t.append(((a_i + half) - U_i) % q)               # рецентрированная цель

    n = len(data)
    dim = n + 1
    # Конструкция Нгуена–Шпарлинского (как в CTF-коде), масштаб ksc ~ q/B:
    #   строка x:  [ksc*A_1, ..., ksc*A_n, 1]     -> в ближайшем векторе coeff = d
    #   n строк:   ksc*q на диагонали             (модуль-редукция по q)
    basis = [[ksc * A[i] for i in range(n)] + [1]]
    for i in range(n):
        row = [0] * dim
        row[i] = ksc * q
        basis.append(row)

    # Целевой вектор u = (ksc*t_1, ..., ksc*t_n, 0)
    target = [ksc * t[i] for i in range(n)] + [0]

    closest = _solve_cvp(basis, target)

    # Последняя координата ближайшего вектора = d  (коэффициент строки x)
    d_cand = closest[-1] % q
    if gost.multiply_point(d_cand, G, a, p) == tuple(Y):
        return d_cand
    return None


# ------------------------------------------------------------------ #
#  Параллельный движок: пул процессов, каждый — своя попытка           #
# ------------------------------------------------------------------ #
_CTX = {}


def _pool_init(data, q, L, p, a, G, Y, base_size, n):
    # Общие read-only данные кладём в глобал один раз на процесс.
    _CTX.update(data=data, q=q, L=L, p=p, a=a, G=G, Y=Y, base=base_size, n=n)


def _pool_worker(seed):
    rng = random.Random(seed)
    n, base = _CTX["n"], _CTX["base"]
    # Варьируем размер подвыборки -> "несколько способов" перебираются сразу.
    size = min(n, max(4, base + rng.randint(-2, 4)))
    subset = rng.sample(_CTX["data"], size)
    d = recover_key(subset, _CTX["q"], _CTX["L"], _CTX["p"],
                    _CTX["a"], _CTX["G"], _CTX["Y"])
    return d, size


# ------------------------------------------------------------------ #
def main():
    if len(sys.argv) > 1:
        path = sys.argv[1]
    else:
        files = sorted(glob.glob("dataset_public_*.txt"), key=os.path.getmtime)
        if not files:
            print("Не найден dataset_public_*.txt — сначала запустите gost.py")
            return
        path = files[-1]

    print("=" * 60)
    print("Атака на ГОСТ Р 34.10-2012 через HNP (решётка, CVP/Бабай)")
    print("=" * 60)
    print(f"Датасет     : {path}")

    q, Y, L, data = load_public(path)
    p, a, b, G = pick_curve(q)
    w = q.bit_length()
    n = len(data)

    print(f"bitlen(q)   = {w}")
    print(f"leak_bits   = {L}  (старших бит нонса известно)")
    print(f"подписей    = {n}  (в файле)")
    print(f"решатель    = {'fpylll (быстрый, C)' if _HAVE_FPYLLL else 'чистый Python'}")
    if not _HAVE_FPYLLL:
        reduction = "только LLL (BKZ недоступен без fpylll)"
    elif BKZ_BLOCK >= 2:
        reduction = f"LLL + BKZ-{BKZ_BLOCK}"
    else:
        reduction = "только LLL (BKZ выключен, BKZ_BLOCK=0)"
    print(f"редукция    = {reduction}")

    # Единая логика для ЛЮБОГО leak_bits: размер подвыборки на попытку.
    # Ветвлений по значению L нет — формула одна для всех.
    size = min(n, max(6, ((w + L - 1) // L) * 3 + 4))
    if size > 60:
        print(f"ВНИМАНИЕ: размерность решётки ~{size + 1} — LLL+Бабай считают долго.")

    workers = os.cpu_count() or 4
    print(f"\nПараллельно: {workers} процесс(ов). Каждый берёт свою случайную "
          f"подвыборку (~{size} из {n}) и слегка разный размер — «несколько")
    print("способов сразу». Первый нашедший ключ побеждает. Стоп — Ctrl+C.\n")

    d_rec = None
    attempt = 0
    t_start = time.time()
    ex = ProcessPoolExecutor(max_workers=workers, initializer=_pool_init,
                             initargs=(data, q, L, p, a, G, Y, size, n))

    def _kill_workers():
        # Немедленно (SIGKILL) прибиваем все процессы-воркеры, чтобы не грели CPU.
        for pr in list(getattr(ex, "_processes", {}).values()):
            try:
                pr.kill()
            except Exception:
                pass
        ex.shutdown(wait=False, cancel_futures=True)

    try:
        while d_rec is None:
            futs = [ex.submit(_pool_worker, random.randrange(1 << 30))
                    for _ in range(workers)]
            for fut in as_completed(futs):
                attempt += 1
                d, sz = fut.result()
                print(f"  попытка {attempt} (размер {sz}, {time.time()-t_start:.0f} с): "
                      f"{'УСПЕХ' if d else 'неудача'}", flush=True)
                if d is not None:
                    d_rec = d
                    break
    except KeyboardInterrupt:
        _kill_workers()
        print(f"\n[STOP] Остановлено после {attempt} попыток, "
              f"{time.time()-t_start:.0f} с.")
        os._exit(0)

    # Ключ найден: сразу гасим воркеры, печатаем и мгновенно выходим.
    _kill_workers()
    elapsed = time.time() - t_start
    print("\n" + "-" * 60)
    print("[OK] Проверка d*G == Y пройдена — секретный ключ восстановлен.")
    print(f"     (найдено с попытки {attempt}, время {elapsed:.1f} с)")
    print("\nВосстановленный секретный ключ x (= d):")
    print(f"  dec : {d_rec}")
    print(f"  hex : {hex(d_rec)}")
    print(f"  bin : {format(d_rec, f'0{w}b')}   <- при желании сравните с 'x' в dataset_secret_*.txt вручную")
    sys.stdout.flush()
    os._exit(0)          # обрываем «догоняющие» процессы, не ждём их


if __name__ == "__main__":
    main()
