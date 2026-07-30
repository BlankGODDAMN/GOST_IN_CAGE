"""
Подписывающий ОРАКУЛ ГОСТ Р 34.10-2012 (уязвим к тайминг-утечке LadderLeak).

Запускается в Docker. Держит секретный ключ x ТОЛЬКО в памяти и НИКОГДА не
отдаёт его (как и нонс k) по сети. Наружу — сырой TCP-чат (совместим с `nc`):

    PUBKEY          -> открытые параметры кривой и открытый ключ Y
    SIGN [msg]      -> трейс "подписания" с двумя метками времени + r, s, e
    HELP            -> справка
    QUIT            -> закрыть соединение

ПОБОЧНЫЙ КАНАЛ (идея 1, чистый/детерминированный, замаскирован под лог):
    В трейсе SIGN печатаются две метки времени: "[hh:mm:ss] начинаю подписывать"
    и "[hh:mm:ss] подпись готова". Их РАЗНИЦА в секундах = bit_length(k) —
    артефакт уязвимой (не constant-time) лестницы, которая делает столько
    шагов, каков bit_length нонса. Ни t, ни k, ни x, ни формулы в трейс НЕ
    попадают: атака сама вычисляет t = (готово - начал) и из него — биты.

Переменные окружения:
    GOST_CURVE = A (512 бит) | B (короткая тестовая, по умолчанию)
    ORACLE_HOST (0.0.0.0)  ORACLE_PORT (31337)
"""

import os
import random
import socket
import threading
from datetime import datetime, timedelta

import gost

CURVE = os.environ.get("GOST_CURVE", "A").upper()
HOST = os.environ.get("ORACLE_HOST", "0.0.0.0")
PORT = int(os.environ.get("ORACLE_PORT", "31337"))
# Квант времени на шаг лестницы (мс). Реальная длительность подписи =
# bit_length(k) * STEP_MS. Мелкий -> быстрая атака; 1000 -> целые секунды (демо).
# Дефолт под кривую: 512-бит (A) — мелкий квант, чтобы подпись не была долгой.
STEP_MS = float(os.environ.get("ORACLE_STEP_MS", "0.2" if CURVE == "A" else "5"))

if CURVE == "A":
    p, a, b, m, q, G = gost.id_tc26_gost_3410_12_512_paramSetA()
    HASH = "streebog512"
else:
    CURVE = "B"
    p, a, b, m, q, G = gost.id_tc26_gost_3410_12_512_paramSetB()
    HASH = "streebog256"

W = q.bit_length()

print("=" * 60, flush=True)
print(f"ОРАКУЛ ГОСТ Р 34.10-2012  |  кривая {CURVE}  |  bitlen(q) = {W}"
      f"  |  квант {STEP_MS} мс/шаг", flush=True)
print("=" * 60, flush=True)
# generate_keys печатает x — это GROUND TRUTH для ОПЕРАТОРА контейнера
# (сверить с восстановленным ключом). По сети x НЕ уходит никогда.
x, Y = gost.generate_keys(q, G, a, p)
print("^-- секрет x напечатан ТОЛЬКО в лог контейнера (по сети не отдаётся).",
      flush=True)
print(f"Слушаю {HOST}:{PORT}. Подключение: nc <host> {PORT}", flush=True)

BANNER = (b"GOST-3410 signing oracle. "
          b"Commands: PUBKEY | SIGN [msg] | HELP | QUIT\n")


def handle(conn, addr):
    try:
        f = conn.makefile("rwb")
        f.write(BANNER)
        f.flush()
        for raw in f:
            line = raw.decode("utf-8", "replace").strip()
            if not line:
                continue
            cmd, _, arg = line.partition(" ")
            cmd = cmd.upper()

            if cmd == "PUBKEY":
                # Всё ПУБЛИЧНОЕ: параметры кривой (стандартные) + открытый ключ.
                out = (f"curve={CURVE}\n"
                       f"p={p:x}\n"
                       f"a={a:x}\n"
                       f"q={q:x}\n"
                       f"Gx={G[0]:x}\n"
                       f"Gy={G[1]:x}\n"
                       f"Yx={Y[0]:x}\n"
                       f"Yy={Y[1]:x}\n"
                       f"END\n")
                f.write(out.encode())
                f.flush()

            elif cmd == "SIGN":
                msg = arg if arg else gost.generate_russian_text(50)
                (r, s), e, k = gost.create_signature(msg, x, G, a, p, q, HASH)
                # РЕАЛЬНЫЙ замер: засекаем старт, реально тратим ~ bit_length(k)
                # * STEP_MS мс (busy-wait — артефакт уязвимой лестницы), засекаем
                # конец. Наружу — только две ИЗМЕРЕННЫЕ метки; их разница = время.
                t0 = datetime.now()
                deadline = t0 + timedelta(milliseconds=k.bit_length() * STEP_MS)
                while datetime.now() < deadline:
                    pass
                t1 = datetime.now()
                out = (f"[{t0:%H:%M:%S.%f}] начинаю подписывать\n"
                       f"· этап 1/3\n"
                       f"· этап 2/3\n"
                       f"· этап 3/3\n"
                       f"[{t1:%H:%M:%S.%f}] подпись готова\n"
                       f"r={r:x}\n"
                       f"s={s:x}\n"
                       f"e={e:x}\n"
                       f"END\n")
                f.write(out.encode())
                f.flush()

            elif cmd in ("QUIT", "EXIT", "BYE"):
                f.write(b"bye\n")
                f.flush()
                break

            elif cmd == "HELP":
                f.write(b"PUBKEY | SIGN [msg] | QUIT\n")
                f.flush()

            else:
                f.write(b"ERR unknown command (try HELP)\n")
                f.flush()
    except (ConnectionError, OSError):
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


def _serve(srv):
    while True:
        try:
            conn, addr = srv.accept()
        except OSError:
            break
        threading.Thread(target=handle, args=(conn, addr), daemon=True).start()


def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, PORT))
    srv.listen(128)

    # Pre-fork: несколько процессов с ОБЩИМ ключом x (сгенерирован до fork),
    # все accept() на одном сокете -> ядро распределяет соединения по процессам.
    # Это даёт настоящий многоядерный сбор (в одном процессе Python упёрся бы в GIL).
    nproc = int(os.environ.get("ORACLE_WORKERS", str(os.cpu_count() or 4)))
    if hasattr(os, "fork") and os.name == "posix" and nproc > 1:
        print(f"Pre-fork: {nproc} процесс(ов) с общим ключом.", flush=True)
        for _ in range(nproc - 1):
            if os.fork() == 0:
                random.seed(os.urandom(16))     # свой независимый поток нонсов
                try:
                    _serve(srv)
                finally:
                    os._exit(0)
        random.seed(os.urandom(16))             # у родителя тоже свой поток
    try:
        _serve(srv)
    except KeyboardInterrupt:
        print("\nОстановлен.", flush=True)
    finally:
        srv.close()


if __name__ == "__main__":
    main()
