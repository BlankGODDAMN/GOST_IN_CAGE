import random


# Алфавит и таблица соответствия
char_to_num = {
    'а': 1, 'б': 2, 'в': 3, 'г': 4, 'д': 5,
    'е': 6, 'ж': 7, 'з': 8, 'и': 9, 'й': 10,
    'к': 11, 'л': 12, 'м': 13, 'н': 14, 'о': 15,
    'п': 16, 'р': 17, 'с': 18, 'т': 19, 'у': 20,
    'ф': 21, 'х': 22, 'ц': 23, 'ч': 24, 'ш': 25,
    'щ': 26, 'ъ': 27, 'ы': 28, 'ь': 29, 'э': 30,
    'ю': 31, 'я': 32
}


# Хеширование сообщения
def hash_message(message, p):
    h = 0
    hash = []
    print("Хеширование (пошагово):")
    for char in message.lower():
        if char in char_to_num:
            Mi = char_to_num[char]
        else:
            Mi = ord(char) % 32  # запасной вариант
        h = (h + Mi) ** 2 % p
        hash.append(h)
    # Преобразуем список в строку без пробелов
    hashstr = ''.join(map(str, hash))
    print(hashstr)
    print(f"Хеш m = h(M): {h}")
    return h


# Проверка числа на простоту
def is_prime(n):
    if n < 2:
        return False
    for i in range(2, int(n ** 0.5) + 1):
        if n % i == 0:
            return False
    return True


# Нахождение обратного элемента по модулю p
def mod_inverse(k, p):
    return pow(k, p - 2, p)


#
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


def find_point_order(P, a, p):
    if P is None:
        return 1

    current = P
    order = 1

    while current is not None:
        current = add_points(current, P, a, p)
        order += 1
        if order > p * 2:
            break

    return order


# Нахождение всех точек на кривой
def find_all_points(a, b, p):
    points = []

    for x in range(p):
        right_side = (pow(x, 3, p) + a * x + b) % p
        for y in range(p):
            if pow(y, 2, p) == right_side:
                if x == 0 and y == 0:
                    continue
                points.append((x, y))
    # print("Точки кривой: ", points)
    return points


# Разложение числа на простые множители
def factorize(n):
    factors = []
    d = 2
    while d * d <= n:
        while n % d == 0:
            factors.append(d)
            n //= d
        d += 1
    if n > 1:
        factors.append(n)
    return factors


# Вычисление количества точек на эллиптической кривой
def find_subgroup_order(a, b, p):
    points = find_all_points(a, b, p)
    n = len(points) + 1  # +1 для точки на бесконечности
    # Находим все простые множители
    factors = factorize(n)
    # Находим наибольший простой множитель
    q = max(factors)
    return q


# Нахождение порядка точки
def find_points_orders(points, a, p):
    orders = {}
    for point in points:
        order = find_point_order(point, a, p)
        orders[point] = order
    return orders


# Выбор точек, пригодных для криптографических целей
def find_cryptographic_points(points, orders):
    suitable = []
    print("\nТочки, пригодные для криптографических целей:")
    for point in points:
        order = orders[point]
        # Проверяем, что порядок > 2 и является простым числом
        if order > 2:
            factors = factorize(order)
            is_prime = (len(factors) == 1 and order > 1)
            if is_prime:
                suitable.append(point)
    print(f"{suitable}")
    return suitable


# Генерация параметров эллиптической кривой
def generate_curve_params():
    # Ввод модуля p (простое число)
    while True:
        try:
            p = int(input("Введите модуль p (простое число): "))
            if not is_prime(p):
                print("Ошибка: p должно быть простым числом!")
                continue
            break
        except ValueError:
            print("Ошибка: введите целое число!")

    # Ввод параметров кривой a и b
    a = int(input("Введите параметр a: "))
    b = int(input("Введите параметр b: "))

    # Находим все точки на кривой
    all_points = find_all_points(a, b, p)
    # Определяем порядки точек
    orders = find_points_orders(all_points, a, p)
    # Находим точки, пригодные для криптографии
    crypto_points = find_cryptographic_points(all_points, orders)
    # Программа ВЫЧИСЛЯЕТ q (порядок подгруппы)
    # Вычисление порядка подгруппы q
    q = find_subgroup_order(a, b, p)

    # Ввод базовой точки G
    while True:
        try:
            Gx, Gy = map(int, input("Введите координаты базовой точки G (x y): ").split())
            G = (Gx, Gy)
            break
        except ValueError:
            print("Ошибка: введите два целых числа через пробел!")

    print(f"Вычисленный порядок подгруппы q = {q}")
    return p, a, b, G, q


# Генерация ключей
def generate_keys(q, G, a, p):
    while True:
        try:
            x = int(input(f"Введите секретный ключ x (1 < x < {q}): "))
            if x <= 1 or x >= q:
                print(f"Ошибка: x должно быть в диапазоне 1 < x < {q}")
                continue
            break
        except ValueError:
            print("Ошибка: введите целое число!")

    # Вычисление открытого ключа Y = [x]G
    Y = multiply_point(x, G, a, p)
    print(f"Открытый ключ Y = {Y}")

    return x, Y


def preprocess_text(text, encrypt_mode=True):
    # Меняем заглавные на строчные
    text = text.lower()

    # Заменяем специальные символы
    if encrypt_mode:
        replacements = {
            '.': 'тчк',
            ',': 'зпт',
            '-': 'трр',
            ':': 'двт',
            ';': 'тсз',
            '!': 'вск',
            '?': 'врс',
            ' ': 'прб'
        }
        for symbol, replacement in replacements.items():
            text = text.replace(symbol, replacement)
    else:
        pass

    return text


# Создание ЭЦП
def create_signature(message, x, G, a, p, q, hash_P):
    # Предобработка текста
    message = message.lower()
    processed = preprocess_text(message, encrypt_mode=True)

    # Хеширование сообщения
    h = hash_message(processed, hash_P)
    Hm = h % q

    if Hm == 0:
        Hm = 1

    # Генерация подписи
    while True:
        # Ввод k
        while True:
            try:
                k = random.randint(1, q - 1)
                if k < 1 or k >= q:
                    print(f"Ошибка: k должно быть в диапазоне 1 ≤ k < {q}")
                    continue
                print(f"k = {k}")
                break
            except ValueError:
                print("Ошибка: введите целое число!")

        # Вычисление точки P = [k]G
        P = multiply_point(k, G, a, p)
        x_P, y_P = P
        print(f"P = [k]G = ({x_P}, {y_P})")

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
    return signature, Hm


# Проверка ЭЦП
def verify_signature(message, signature, Y, G, a, p, q, hash_P):
    r, s = signature

    # Проверка корректности r и s
    if r <= 0 or r >= q or s <= 0 or s >= q:
        print(f"Ошибка: r или s вне допустимого диапазона (0, {q})")
        return False, None, None

    # Предобработка текста
    message = message.lower()
    processed = preprocess_text(message, encrypt_mode=True)

    # Хеширование сообщения
    h = hash_message(processed, hash_P)
    Hm = h % q

    if Hm == 0:
        Hm = 1

    # Вычисление h^(-1) mod q
    h_inv = mod_inverse(Hm, q)

    # Вычисление u1 и u2
    u1 = (s * h_inv) % q
    u2 = (-r * h_inv) % q

    # Вычисление P = [u1]G + [u2]Y
    point1 = multiply_point(u1, G, a, p)
    point2 = multiply_point(u2, Y, a, p)
    P = add_points(point1, point2, a, p)

    if P is None:
        print("P = 0 (точка на бесконечности) - подпись неверна")
        return False, None, None

    x_P, y_P = P

    # Проверка
    x_P_mod_q = x_P % q

    is_valid = (x_P_mod_q == r)

    return is_valid, x_P_mod_q, r


def main():
    print("\n" + "=" * 40)
    print("ЭЦП ГОСТ Р 34.10-2012")
    print("=" * 40)
    print("\nВыберите действие:")
    print("1 - Создать ЭЦП")
    print("2 - Проверить ЭЦП")

    choice = input("Ваш выбор (1-2): ")

    # РЕЖИМ СОЗДАНИЯ ПОДПИСИ
    if choice == '1':
        # Ввод параметров кривой
        p, a, b, G, q = generate_curve_params()

        # Ввод секретного ключа
        x, Y = generate_keys(q, G, a, p)

        # Ввод модуля для хеширования
        hash_P = p

        # Ввод сообщения
        message = input("Введите сообщение M: ")

        # Создание подписи
        signature, Hm = create_signature(message, x, G, a, p, q, hash_P)
        r, s = signature

        print("\nРезультат:")
        print(f"Подпись S = (r, s): ({r}, {s})")

    # РЕЖИМ ПРОВЕРКИ ПОДПИСИ
    else:
        # Ввод параметров кривой
        print("\nВведите параметры эллиптической кривой:")
        p = int(input("Введите модуль p: "))
        a = int(input("Введите параметр a: "))
        b = int(input("Введите параметр b: "))
        Gx, Gy = map(int, input("Введите координаты базовой точки G (x y): ").split())
        G = (Gx, Gy)
        q = int(input("Введите порядок подгруппы q: "))

        # Ввод открытого ключа
        Yx, Yy = map(int, input("Введите координаты открытого ключа Y (x y): ").split())
        Y = (Yx, Yy)

        # Ввод модуля для хеширования
        hash_P = p

        # Ввод сообщения
        message = input("Введите сообщение M: ")

        # Ввод подписи
        r, s = map(int, input("Введите подпись (r s): ").split())
        signature = (r, s)

        # Проверка подписи
        is_valid, x_P_mod_q, r_val = verify_signature(message, signature, Y, G, a, p, q, hash_P)

        print("\nРезультат:")
        if is_valid:
            print(f"  x_P mod q = {x_P_mod_q} = r = {r_val}")
            print("✓ ПОДПИСЬ ВЕРНА! Сообщение подлинное.")
        else:
            if x_P_mod_q is not None:
                print(f"  x_P mod q = {x_P_mod_q} ≠ r = {r_val}")
            print("✗ ПОДПИСЬ НЕВЕРНА! Сообщение было изменено.")

    print("=" * 40)


if __name__ == "__main__":
    main()

