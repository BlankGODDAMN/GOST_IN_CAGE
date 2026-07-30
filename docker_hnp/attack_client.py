"""
Автоматическая АТАКА (на ХОСТЕ) на подписывающий оракул ГОСТ Р 34.10-2012.
САМОДОСТАТОЧНЫЙ скрипт: ничего не импортирует из проекта — вся атака здесь.

Полная end-to-end симуляция LadderLeak:
  1) подключается к оракулу по TCP (как nc);
  2) МНОГОПОТОЧНО шлёт SIGN и из ДВУХ меток времени в трейсе САМА мерит задержку,
     сама калибрует квант и оценивает t = bit_length(нонса);
  3) сама решает, у каких подписей старшие L бит нонса нулевые
     (lz = w - t >= L), и берёт их как HNP-образцы (известные старшие биты = 0);
  4) решёткой (CVP: LLL/BKZ + Babai) восстанавливает ключ d;
  5) проверяет ТОЛЬКО по открытому ключу: d*G == Y.

Оракул НЕ отдаёт ни t, ни нонс, ни секрет — всё вычисляет атака.

Улучшения этой версии:
  * многопоточный сбор (несколько соединений к многопроцессному оракулу);
  * КЭШ собранного пула на диск (pool_<curve>_L<L>.json) — повторный запуск
    не пересобирает подписи, если ключ (Y) и L совпали;
  * ограничение числа воркеров решётки (env LATTICE_WORKERS) — против свопа mpfr.

Запуск:  python3 attack_client.py [L] [bkz]
Env:     ORACLE_HOST (127.0.0.1)  ORACLE_PORT (31337)
         HARVEST_THREADS (=CPU)   LATTICE_WORKERS (=min(CPU,4))
"""

import json
import os
import random
import re
import socket
import statistics
import sys
import threading
import time
from concurrent.futures import (ProcessPoolExecutor, ThreadPoolExecutor,
                                as_completed)
from fractions import Fraction

# Быстрый решатель через fpylll (C-библиотека). Нет — откат на чистый Python.
try:
    from fpylll import (IntegerMatrix, LLL as _FP_LLL, BKZ as _FP_BKZ,
                        CVP as _FP_CVP, FPLLL as _FPLLL)
    _HAVE_FPYLLL = True
except Exception:
    _HAVE_FPYLLL = False

BKZ_BLOCK = 0                                    # 0 = только LLL

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

_HERE = os.path.dirname(os.path.abspath(__file__))
HOST = os.environ.get("ORACLE_HOST", "127.0.0.1")
PORT = int(os.environ.get("ORACLE_PORT", "31337"))
TS_RE = re.compile(r"\[(\d\d):(\d\d):(\d\d)\.(\d+)\]")
_CPU = os.cpu_count() or 4
HARVEST_THREADS = int(os.environ.get("HARVEST_THREADS", str(_CPU)))
LATTICE_WORKERS = int(os.environ.get("LATTICE_WORKERS", str(min(_CPU, 4))))


# ================================================================== #
#  Эллиптическая кривая над F_p (только для проверки d*G == Y)         #
# ================================================================== #
def mod_inverse(k, p):
    return pow(k, p - 2, p)


def add_points(P, Q, a, p):
    if P is None:
        return Q
    if Q is None:
        return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2 and (y1 + y2) % p == 0:
        return None
    if x1 == x2 and y1 == y2:
        num = (3 * x1 * x1 + a) % p
        den = (2 * y1) % p
    else:
        num = (y2 - y1) % p
        den = (x2 - x1) % p
    lam = (num * mod_inverse(den, p)) % p
    x3 = (lam * lam - x1 - x2) % p
    y3 = (lam * (x1 - x3) - y1) % p
    return (x3, y3)


def multiply_point(k, P, a, p):
    if P is None or k == 0:
        return None
    result = None
    current = P
    kb = k
    while kb > 0:
        if kb & 1:
            result = add_points(result, current, a, p)
        current = add_points(current, current, a, p)
        kb >>= 1
    return result


# ================================================================== #
#  Решётка: целочисленный LLL (Cohen 2.6.7) + Грам-Шмидт + Бабай      #
# ================================================================== #
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
    dim = len(target)
    Bstar, norms = _gram_schmidt(basis)
    b = [Fraction(x) for x in target]
    for i in range(len(basis) - 1, -1, -1):
        c = round(sum(b[k] * Bstar[i][k] for k in range(dim)) / norms[i])
        b = [b[k] - c * basis[i][k] for k in range(dim)]
    return [int(target[k] - b[k]) for k in range(dim)]


def _solve_cvp(basis, target):
    """Ближайший вектор решётки к target (fpylll: >200 бит -> mpfr/heuristic)."""
    if _HAVE_FPYLLL:
        M = IntegerMatrix.from_matrix([list(map(int, row)) for row in basis])
        maxbits = max(abs(x) for row in basis for x in row).bit_length()
        if maxbits > 200:
            _FPLLL.set_precision(maxbits)
            _FP_LLL.reduction(M, method="heuristic", float_type="mpfr")
            if BKZ_BLOCK >= 2:
                _FP_BKZ.reduction(M, _FP_BKZ.Param(
                    block_size=min(len(basis), BKZ_BLOCK), float_type="mpfr"))
        else:
            _FP_LLL.reduction(M)
            if BKZ_BLOCK >= 2:
                _FP_BKZ.reduction(M, _FP_BKZ.Param(
                    block_size=min(len(basis), BKZ_BLOCK)))
        return list(_FP_CVP.closest_vector(M, tuple(int(x) for x in target)))
    return babai_nearest_plane(lll_int(basis), target)


def recover_key(data, q, L, p, a, G, Y):
    """Одна попытка HNP-решётки на подвыборке подписей. Возврат d или None."""
    m = q.bit_length()
    B = 1 << (m - L)
    half = B >> 1
    ksc = max(1, q // B)

    A, t = [], []
    for s in data:
        e_inv = pow(s["e"], -1, q)
        A.append((-e_inv * s["r"]) % q)
        U_i = (e_inv * s["s"]) % q
        a_i = s["leak"] << (m - L)
        t.append(((a_i + half) - U_i) % q)

    n = len(data)
    dim = n + 1
    basis = [[ksc * A[i] for i in range(n)] + [1]]
    for i in range(n):
        row = [0] * dim
        row[i] = ksc * q
        basis.append(row)
    target = [ksc * t[i] for i in range(n)] + [0]

    closest = _solve_cvp(basis, target)
    d_cand = closest[-1] % q
    if multiply_point(d_cand, G, a, p) == tuple(Y):
        return d_cand
    return None


# ================================================================== #
#  Транспорт: разговор с оракулом по TCP                               #
# ================================================================== #
def _connect():
    s = socket.create_connection((HOST, PORT))
    f = s.makefile("rwb")
    f.readline()                                 # баннер
    return s, f


def _read_block(f):
    lines = []
    for raw in f:
        line = raw.decode("utf-8", "replace").rstrip("\r\n")
        if line.strip() == "END":
            break
        lines.append(line)
    return lines


def get_pubkey(f):
    """Все параметры атаки берём ТОЛЬКО из публичного ответа оракула."""
    f.write(b"PUBKEY\n")
    f.flush()
    d = {}
    for line in _read_block(f):
        if "=" in line:
            k, v = line.split("=", 1)
            d[k.strip()] = v.strip()
    p = int(d["p"], 16)
    a = int(d["a"], 16)
    q = int(d["q"], 16)
    G = (int(d["Gx"], 16), int(d["Gy"], 16))
    Y = (int(d["Yx"], 16), int(d["Yy"], 16))
    return p, a, q, G, Y, d.get("curve", "?")


def _ts_to_us(h, mnt, s, frac):
    micros = int((frac + "000000")[:6])
    return (((h * 60 + mnt) * 60 + s) * 1_000_000) + micros


def sign_once(f, msg=None):
    f.write((("SIGN " + msg) if msg else "SIGN").encode() + b"\n")
    f.flush()
    stamps, kv = [], {}
    for line in _read_block(f):
        m = TS_RE.search(line)
        if m:
            stamps.append(_ts_to_us(int(m.group(1)), int(m.group(2)),
                                    int(m.group(3)), m.group(4)))
        elif "=" in line:
            k, v = line.split("=", 1)
            kv[k.strip()] = v.strip()
    elapsed_ms = ((stamps[-1] - stamps[0]) % 86_400_000_000) / 1000.0
    return int(kv["r"], 16), int(kv["s"], 16), int(kv["e"], 16), elapsed_ms


# ================================================================== #
#  Кэш собранного пула на диск                                        #
# ================================================================== #
def _pool_path(curve, L):
    return os.path.join(_HERE, f"pool_{curve}_L{L}.json")


def save_pool(path, q, Y, p, a, G, L, good):
    obj = {"q": hex(q), "Y": [hex(Y[0]), hex(Y[1])],
           "p": hex(p), "a": hex(a), "G": [hex(G[0]), hex(G[1])], "L": L,
           "samples": [{"r": hex(s["r"]), "s": hex(s["s"]), "e": hex(s["e"])}
                       for s in good]}
    with open(path, "w", encoding="utf-8") as fp:
        json.dump(obj, fp)


def load_pool(path, q, Y, L):
    if not os.path.exists(path):
        return None
    try:
        d = json.load(open(path, encoding="utf-8"))
        if (int(d["q"], 16) != q or d["L"] != L
                or int(d["Y"][0], 16) != Y[0] or int(d["Y"][1], 16) != Y[1]):
            return None                          # пул от другого ключа/L
        return [{"r": int(s["r"], 16), "s": int(s["s"], 16),
                 "e": int(s["e"], 16), "leak": 0} for s in d["samples"]]
    except Exception:
        return None


# ================================================================== #
#  Сбор образцов: калибровка + МНОГОПОТОЧНЫЙ сбор                      #
# ================================================================== #
def calibrate_step(elapseds, w):
    seed = sorted(elapseds)[int(len(elapseds) * 0.97)] / w
    step = max(seed, 1e-4)
    for _ in range(6):
        ts = [max(1, round(e / step)) for e in elapseds]
        step = statistics.median(e / t for e, t in zip(elapseds, ts))
    return step


def harvest(w, L, need, threads, warmup=150):
    # Фаза 1: калибровка кванта на одном соединении.
    s0, f0 = _connect()
    print(f"  разогрев {warmup} подписей для калибровки кванта...", flush=True)
    raw = [sign_once(f0) for _ in range(warmup)]
    step = calibrate_step([r[3] for r in raw], w)
    print(f"  оценён квант ≈ {step:.4f} мс/шаг", flush=True)

    good, lock, stop = [], threading.Lock(), threading.Event()
    total = [warmup]
    t0 = time.time()

    def consider(r, s, e, el):
        if w - round(el / step) >= L:            # >= L ведущих нулей нонса
            with lock:
                good.append({"r": r, "s": s, "e": e, "leak": 0})
                if len(good) >= need:
                    stop.set()

    for (r, s, e, el) in raw:                    # переиспользуем разогрев
        consider(r, s, e, el)

    def collector(f):
        while not stop.is_set():
            try:
                r, s, e, el = sign_once(f)
            except Exception:
                break
            with lock:
                total[0] += 1
                n = total[0]
            consider(r, s, e, el)
            if n % 500 == 0:
                print(f"  запрошено {n}, годных {len(good)}/{need} "
                      f"({time.time()-t0:.0f} с)", flush=True)

    # Фаза 2: несколько соединений (первое переиспользуем) собирают параллельно.
    conns = [(s0, f0)] + [_connect() for _ in range(max(0, threads - 1))]
    print(f"  сбор в {len(conns)} поток(ов)...", flush=True)
    with ThreadPoolExecutor(max_workers=len(conns)) as ex:
        futs = [ex.submit(collector, f) for (_, f) in conns]
        for fut in futs:
            fut.result()
    for (s, f) in conns:
        try:
            f.write(b"QUIT\n")
            f.flush()
        except Exception:
            pass
        s.close()
    print(f"  собрано {len(good)} годных из {total[0]} запросов "
          f"(доля {len(good)/max(1,total[0]):.2%}, {time.time()-t0:.0f} с)",
          flush=True)
    return good[:need], total[0]


# ================================================================== #
#  Параллельный движок решётки                                        #
# ================================================================== #
_CTX = {}


def _init(data, q, L, p, a, G, Y, size, bkz):
    global BKZ_BLOCK
    BKZ_BLOCK = bkz
    _CTX.update(data=data, q=q, L=L, p=p, a=a, G=G, Y=Y, size=size)


def _worker(seed):
    rng = random.Random(seed)
    n, base = len(_CTX["data"]), _CTX["size"]
    size = min(n, max(6, base + rng.randint(-2, 4)))
    subset = rng.sample(_CTX["data"], size)
    d = recover_key(subset, _CTX["q"], _CTX["L"], _CTX["p"],
                    _CTX["a"], _CTX["G"], _CTX["Y"])
    return d, size


# ================================================================== #
def main():
    L_arg = int(sys.argv[1]) if len(sys.argv) > 1 else None
    bkz = int(sys.argv[2]) if len(sys.argv) > 2 else 0

    print("=" * 60)
    print("АТАКА (хост) на оракул ГОСТ — LadderLeak через решётку (один файл)")
    print("=" * 60)
    print(f"оракул      : {HOST}:{PORT}")

    ps, pf = _connect()
    p, a, q, G, Y, curve = get_pubkey(pf)
    try:
        pf.write(b"QUIT\n")
        pf.flush()
    except Exception:
        pass
    ps.close()
    w = q.bit_length()                           # атака сама выводит w из q

    L_req = L_arg if L_arg is not None else (6 if w > 64 else 3)
    L = min(L_req, w - 1)
    subset = min(max(6, (w + L - 1) // L + 3), w)
    need = subset + max(4, subset // 2)
    est_q = need * (1 << L)
    print(f"кривая      : {curve}   bitlen(q) = {w}")
    print(f"leak L      : {L}  (берём подписи с >= L ведущими нулями нонса)")
    print(f"подвыборка  : ~{subset}   пул образцов: {need}")
    print(f"ожид.запросов ≈ {est_q:,}  (растёт как 2^L)")
    print(f"решатель    : {'fpylll' if _HAVE_FPYLLL else 'чистый Python'}"
          f"   BKZ = {bkz or 'выкл'}")
    print(f"потоки сбора : {HARVEST_THREADS}   воркеры решётки: {LATTICE_WORKERS}\n")

    # Кэш пула: если для этого ключа (Y) и L уже собрано — пропускаем сбор.
    path = _pool_path(curve, L)
    good = load_pool(path, q, Y, L)
    if good is not None and len(good) >= subset:
        print(f"Загружен пул из {os.path.basename(path)}: "
              f"{len(good)} образцов (сбор пропущен).\n")
    else:
        print("Сбор подписей (t мерится из меток времени в трейсе оракула):")
        good, _ = harvest(w, L, need, HARVEST_THREADS)
        save_pool(path, q, Y, p, a, G, L, good)
        print(f"Пул сохранён в {os.path.basename(path)} "
              f"({len(good)} образцов) — повторный запуск не будет пересобирать.\n")

    workers = max(1, LATTICE_WORKERS)
    print(f"Решётка: {workers} процесс(ов), первый нашедший d*G==Y побеждает.\n")

    d_rec, attempt = None, 0
    t_start = time.time()
    ex = ProcessPoolExecutor(max_workers=workers, initializer=_init,
                             initargs=(good, q, L, p, a, G, Y, subset, bkz))

    def _kill():
        for pr in list(getattr(ex, "_processes", {}).values()):
            try:
                pr.kill()
            except Exception:
                pass
        ex.shutdown(wait=False, cancel_futures=True)

    try:
        while d_rec is None:
            futs = [ex.submit(_worker, random.randrange(1 << 30))
                    for _ in range(workers)]
            for fut in as_completed(futs):
                attempt += 1
                d, sz = fut.result()
                print(f"  попытка {attempt} (размер {sz}, "
                      f"{time.time()-t_start:.0f} с): "
                      f"{'УСПЕХ' if d else 'неудача'}", flush=True)
                if d is not None:
                    d_rec = d
                    break
    except KeyboardInterrupt:
        _kill()
        print(f"\n[STOP] после {attempt} попыток, {time.time()-t_start:.0f} с."
              f"  (пул сохранён — повторный запуск начнёт сразу с решётки)")
        os._exit(0)

    _kill()
    print("\n" + "-" * 60)
    print("[OK] d*G == Y — секретный ключ восстановлен.")
    print(f"     (попытка {attempt}, {time.time()-t_start:.1f} с)")
    print(f"  dec : {d_rec}")
    print(f"  hex : {hex(d_rec)}")
    sys.stdout.flush()
    os._exit(0)


if __name__ == "__main__":
    main()
