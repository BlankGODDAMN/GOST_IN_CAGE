import random
import hashlib
from gostcrypto import gosthash

# Хеширование сообщения стрибог
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

    # Преобразуем в число
    hash_int = int.from_bytes(hash_bytes, 'big')

    # Приводим к модулю q
    h = hash_int % q
    return h


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
def create_signature(message, x, G, a, p, q, hash_P, hash_type='streebog512'):
    # Хеширование сообщения
    Hm = hash_message(message, hash_P, hash_type)

    if Hm == 0:
        Hm = 1

    # Генерация подписи
    while True:
        # Ввод k
        while True:
            k = random.randint(1, q - 1)
            if 1 < k < q:
                break

        # Вычисление точки P = [k]G
        P = multiply_point(k, G, a, p)
        x_P, y_P = P

        # Вычисление r = x_P mod q
        r = x_P % q
        if r == 0:
            continue

        # Вычисление s = (k*h + r*x) mod q
        s = (k * Hm + r * x) % q
        if s == 0:
            continue
        break

    signature = (r, s)
    return signature, Hm, k


def main():
    print("\n" + "=" * 40)
    print("ЭЦП ГОСТ Р 34.10-2012")
    print("=" * 40)
    print("\nСоздать ЭЦП")
    print("\nДлина параметров элептической кривой")
    print("1 - Длинные")
    print("2 - Короткие")

    choice = input("(1-2): ")
    if choice == '1':
        # Параметры функции
        p, a, b, m, q, G = id_tc26_gost_3410_12_512_paramSetA()
        hash_type = 'streebog512'

    if choice == '2':
        p, a, b, m, q, G = id_tc26_gost_3410_12_512_paramSetB()
        hash_type = 'streebog256'

    # Ввод модуля для хеширования
    hash_P = p

    # Генерируем ключи
    x, Y = generate_keys(q, G, a, p)

    #Количество пар k/подпись на секретный ключ
    count = int(input("Количество пар k/подпись: "))

    # Имя файла для записи
    filename = f"signatures_x_{hex(x)[:10]}.txt"

    # Открываем файл для записи
    with open(filename, 'w', encoding='utf-8') as f:
        # Записываем x
        f.write(f"x = {x:0{bit_length}b}\n\n")

        # Временные списки для хранения
        signatures = []
        k_values = []

        for i in range(count):
            # Ввод сообщения
            message = generate_russian_text(50)

            # Создание подписи
            signature, Hm, k = create_signature(message, x, G, a, p, q, hash_P, hash_type)
            r, s = signature

            # Сохраняем k и подпись
            k_values.append(k)
            signatures.append((r, s))

            # Записываем в файл k
            f.write(f"k{i + 1} = {k:0{bit_length}b}\n")

        # Записываем в файл подпись
        for i, (r, s) in enumerate(signatures, 1):
            f.write(f"S{i + 1} = ({r:0{bit_length}b},\n {s:0{bit_length}b})\n")


    print(f"\nРезультат записан в файл: {filename} ")


if __name__ == "__main__":
    main()
