import random
import hashlib
from gostcrypto import gosthash

# Хеширование сообщения (Стрибог).
# Приведение по модулю q — ГОСТ Р 34.10-2012, п. 6.1, формула (15).
def hash_message(message, q, hash_type='streebog512'):
    # Кодируем в байты
    msg_bytes = message.encode('utf-8')

    # Выбираем тип хеширования
    if hash_type == 'streebog512':
        hash_obj = gosthash.new('streebog512')
    else:
        hash_obj = gosthash.new('streebog256')

    hash_obj.update(msg_bytes)
    hash_bytes = hash_obj.digest()

    # Преобразуем в число и приводим по модулю q (НЕ p!)
    hash_int = int.from_bytes(hash_bytes, 'big')
    return hash_int % q


# Сколько старших бит нонса "утекает" (симуляция сайд-канала LadderLeak).
LEAK_BITS = 256


# Двоичная запись фиксированной ширины (сохраняет ведущие нули).
def bits(value, width):
    return format(value, f'0{width}b')


# Нахождение обратного элемента по модулю p
def mod_inverse(k, p):
    return pow(k, p - 2, p)


# Cложение точек кривой
def add_points(P, Q, a, p):
    if P is None:
        return Q
    if Q is None:
        return P

    x1, y1 = P
    x2, y2 = Q

    # Случай, когда P = -Q
    if x1 == x2 and (y1 + y2) % p == 0:
        return None

    # Вычисление углового коэффициента
    if x1 == x2 and y1 == y2:
        # Удвоение точки
        numerator = (3 * x1 * x1 + a) % p
        denominator = (2 * y1) % p
    else:
        # Сложение разных точек
        numerator = (y2 - y1) % p
        denominator = (x2 - x1) % p

    lam = (numerator * mod_inverse(denominator, p)) % p

    x3 = (lam * lam - x1 - x2) % p
    y3 = (lam * (x1 - x3) - y1) % p

    return (x3, y3)


# Умножение точки на скаляр
def multiply_point(k, P, a, p):
    if P is None or k == 0:
        return None

    result = None
    current = P
    k_bin = k

    while k_bin > 0:
        if k_bin & 1:
            result = add_points(result, current, a, p)
        current = add_points(current, current, a, p)
        k_bin >>= 1

    return result


# Параметры эллиптической кривой (большие)
def id_tc26_gost_3410_12_512_paramSetA():
    p = 0x00FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC7
    a = 0x00FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC4
    b = 0x00E8C2505DEDFC86DDC1BD0B2B6667F1DA34B82574761CB0E879BD081CFD0B6265EE3CB090F30D27614CB4574010DA90DD862EF9D4EBEE4761503190785A71C760
    m = 0x00FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF27E69532F48D89116FF22B8D4E0560609B4B38ABFAD2B85DCACDB1411F10B275
    q = 0x00FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF27E69532F48D89116FF22B8D4E0560609B4B38ABFAD2B85DCACDB1411F10B275
    Gx = 0x03
    Gy = 0x7503CFE87A836AE3A61B8816E25450E6CE5E1C93ACF1ABC1778064FDCBEFA921DF1626BE4FD036E93D75E6A50E3A41E98028FE5FC235F5B889A589CB5215F2A4
    G = (Gx, Gy)
    return p, a, b, m, q, G

# Параметры эллиптической кривой (короткие)
def id_tc26_gost_3410_12_512_paramSetB():
    p = 3390272539
    a = 3142283494
    b = 2595209411
    m = 3390233545
    q = 23380921
    Gx = 2739299112
    Gy = 2772655963

    G = (Gx, Gy)
    return p, a, b, m, q, G


# Генерация ключей
def generate_keys(q, G, a, p):
    while True:
        x = random.randint(1, q - 1)
        if 1 < x < q:
            break
    print(f"Секретный ключ x = {x}")

    # Вычисление открытого ключа Y = [x]G
    Y = multiply_point(x, G, a, p)

    return x, Y

# текст генерируется без спец символов.
def generate_russian_text(length=50):
    russian_letters = 'абвгдеёжзийклмнопрстуфхцчшщъыьэюя'

    # Генерируем случайную строку
    text = ''.join(random.choice(russian_letters) for _ in range(length))

    return text


# Создание ЭЦП
def create_signature(message, x, G, a, p, q, hash_type='streebog512'):
    # e = H(M) mod q  (п. 6.1, формула (15)); если e = 0, то e = 1
    e = hash_message(message, q, hash_type)
    if e == 0:
        e = 1

    # Генерация подписи
    while True:
        # Однократный ключ (нонс) k
        k = random.randint(1, q - 1)

        # C = [k]G,  r = x_C mod q
        C = multiply_point(k, G, a, p)
        r = C[0] % q
        if r == 0:
            continue

        # s = (r*x + k*e) mod q
        s = (r * x + k * e) % q
        if s == 0:
            continue
        break

    return (r, s), e, k


def main():
    import secrets

    print("\n" + "=" * 40)
    print("ЭЦП ГОСТ Р 34.10-2012")
    print("=" * 40)
    print("\nДлина параметров эллиптической кривой")
    print("1 - Длинные (512 бит)")
    print("2 - Короткие (тестовая кривая)")

    choice = input("(1-2): ")
    if choice == '2':
        p, a, b, m, q, G = id_tc26_gost_3410_12_512_paramSetB()
        hash_type = 'streebog256'
    else:
        p, a, b, m, q, G = id_tc26_gost_3410_12_512_paramSetA()
        hash_type = 'streebog512'

    w = q.bit_length()               # ширина всех чисел (бит)
    L = min(LEAK_BITS, w - 1)        # не больше bitlen(q)-1

    # Генерируем ключи
    x, Y = generate_keys(q, G, a, p)

    # Количество пар k/подпись на секретный ключ
    count = int(input("Количество пар k/подпись: "))

    # Имена файлов — НЕ производные от x (иначе секрет утечёт в имя)
    tag = secrets.token_hex(4)
    pub_name = f"dataset_public_{tag}.txt"   # то, что видит атакующий
    sec_name = f"dataset_secret_{tag}.txt"   # ground-truth, атакой не читается

    with open(pub_name, 'w', encoding='utf-8') as pub, \
         open(sec_name, 'w', encoding='utf-8') as sec:

        # --- Публичный файл: вход для атаки HNP ---
        pw = p.bit_length()          # координаты точки — элементы поля F_p
        pub.write(f"# ГОСТ Р 34.10-2012. Публичные данные для атаки HNP.\n")
        pub.write(f"# r,s,e — ширина {w} бит (mod q); Yx,Yy — {pw} бит (поле F_p).\n")
        pub.write(f"q = {bits(q, w)}\n")
        pub.write(f"Yx = {bits(Y[0], pw)}\n")
        pub.write(f"Yy = {bits(Y[1], pw)}\n")
        pub.write(f"leak_bits = {L}\n\n")

        # --- Секретный файл: только для проверки результата ---
        sec.write("# GROUND TRUTH — атакой НЕ используется, только для проверки.\n")
        sec.write(f"x = {bits(x, w)}\n\n")

        for i in range(count):
            message = generate_russian_text(50)
            (r, s), e, k = create_signature(message, x, G, a, p, q, hash_type)

            # Утечка сайд-канала: старшие L бит нонса k
            leak = k >> (w - L)

            # Публичное: подпись, хэш и биты утечки (фикс. ширина!)
            pub.write(f"S{i + 1} = ({bits(r, w)}, {bits(s, w)})\n")
            pub.write(f"e{i + 1} = {bits(e, w)}\n")
            pub.write(f"leak{i + 1} = {bits(leak, L)}\n\n")

            # Секретное: полный нонс как эталон
            sec.write(f"k{i + 1} = {bits(k, w)}\n")

    print(f"\nПубличные данные (для атаки): {pub_name}")
    print(f"Секрет (ground-truth):        {sec_name}")


if __name__ == "__main__":
    main()
