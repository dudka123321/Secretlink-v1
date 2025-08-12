import re
import base64
import argparse
import requests
import binascii
import os
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

# ===============================
# 📌 Регулярное выражение для поиска URL и путей в JS коде
# ===============================
pattern = re.compile(
    r"""(?:"|')((?:[a-zA-Z]{1,10}://|//)[^"'\s]{1,}
    |(?:/|\.\./|\./)[^"'\s<>]{1,}
    |[a-zA-Z0-9_\-]+(?:\.[a-zA-Z]{2,})(?:/[^"'\s]*)?)["']""",
    re.VERBOSE
)

# ===============================
# 📌 Ключевые слова для поиска секретов
# ===============================
SECRET_KEYWORDS = [
    "api_key", "apikey", "api-key", "secret", "token", "auth", "password",
    "passwd", "pwd", "admin", "access_token", "auth_token", "client_secret",
    "private_key", "jwt", "sessionid", "cookie", "secret_key"
]

# ===============================
# 📌 Нормализация URL (добавляет https:// если нет протокола)
# ===============================
def normalize_url(url):
    if not url.startswith(("http://", "https://")):
        return "https://" + url
    return url

# ===============================
# 📌 Получение JS-кода с сайта или из файла
# ===============================
def get_js_content(source):
    if not source.startswith("http") and ("/" in source or "." in source):
        source = "https://" + source

    if source.startswith("http"):
        resp = requests.get(source)
        resp.raise_for_status()
        return resp.text
    else:
        with open(source, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()

# ===============================
# 📌 Извлечение конечных точек (эндпоинтов)
# ===============================
def extract_endpoints(js_code, base_url=None):
    matches = re.findall(pattern, js_code)
    results = set()
    for match in matches:
        if base_url:
            results.add(urljoin(base_url, match))
        else:
            results.add(match)
    return results

# ===============================
# 📌 Получение базового URL из полного
# ===============================
def get_base_url(url):
    parsed = urlparse(url)
    path = parsed.path
    if "/" in path:
        path = path.rsplit("/", 1)[0] + "/"
    else:
        path = "/"
    base = f"{parsed.scheme}://{parsed.netloc}{path}"
    return base

# ===============================
# 📌 Поиск секретов по ключевым словам
# ===============================
def find_secrets(js_code):
    found = set()
    for keyword in SECRET_KEYWORDS:
        # Ищем в любом регистре
        pattern = re.compile(rf"{keyword}['\"]?\s*[:=]\s*['\"]([^'\"]+)['\"]", re.I)
        for m in pattern.findall(js_code):
            found.add(f"{keyword}: {m}")
    return found

# ===============================
# 📌 Декодирование base64 и других популярных кодировок (URL, hex)
# ===============================
def decode_encoded_strings(js_code):
    decoded_strings = set()
    # Ищем base64-подобные строки (более 8 символов и кратные 4)
    base64_pattern = re.compile(r'([A-Za-z0-9+/=]{8,})')
    for b64 in base64_pattern.findall(js_code):
        try:
            # Пробуем декодировать base64
            decoded = base64.b64decode(b64).decode('utf-8')
            if len(decoded) > 4:  # Отфильтруем короткие мусорные строки
                decoded_strings.add(decoded)
        except Exception:
            pass

    # Ищем URL-кодированные строки
    url_encoded_pattern = re.compile(r'%[0-9a-fA-F]{2,}')
    for match in url_encoded_pattern.findall(js_code):
        try:
            decoded = requests.utils.unquote(match)
            decoded_strings.add(decoded)
        except Exception:
            pass

    # Ищем hex-кодированные строки (например, \x41\x42)
    hex_pattern = re.compile(r'(?:\\x[0-9a-fA-F]{2})+')
    for match in hex_pattern.findall(js_code):
        try:
            hex_str = match.replace("\\x", "")
            bytes_obj = bytes.fromhex(hex_str)
            decoded = bytes_obj.decode('utf-8')
            decoded_strings.add(decoded)
        except Exception:
            pass

    return decoded_strings

# ===============================
# 📌 Проверка эндпоинтов на активность (HTTP статус 200)
# ===============================
def check_endpoint_active(url):
    try:
        resp = requests.head(url, timeout=5, allow_redirects=True)
        if resp.status_code == 200:
            return url
    except Exception:
        pass
    return None

# ===============================
# 📌 Функция для печати логотипа
# ===============================
def print_logo():
    logo = r"""
  _____                 _             _       
 / ____|               | |           | |      
| (___   ___  ___ _   _| | ___  _ __ | |_ ___ 
 \___ \ / _ \/ __| | | | |/ _ \| '_ \| __/ __|
 ____) |  __/ (__| |_| | | (_) | | | | |_\__ \
|_____/ \___|\___|\__,_|_|\___/|_| |_|\__|___/
                                              
"""
    print(logo)
    print("SecretLink - JS Endpoint & Secrets Extractor\n")

# ===============================
# 📌 Создание директорий для сохранения результатов
# ===============================
def prepare_output_dirs(base_dir):
    dirs = {
        "endpoints": os.path.join(base_dir, "endpoints"),
        "active": os.path.join(base_dir, "active"),
        "secrets": os.path.join(base_dir, "secrets"),
    }
    for d in dirs.values():
        os.makedirs(d, exist_ok=True)
    return dirs

# ===============================
# 📌 Основная логика
# ===============================
def main():
    print_logo()

    parser = argparse.ArgumentParser(
        description="SecretLink - Extract JS endpoints and secrets with optional active checking"
    )

    parser.add_argument("-u", "--url", help="Один URL для сканирования")
    parser.add_argument("-l", "--list", help="Файл со списком URL для сканирования")
    parser.add_argument("-b", "--base", help="Базовый URL для относительных путей")
    parser.add_argument("-a", "--active", action="store_true", help="Проверять активность эндпоинтов")
    parser.add_argument("-o", "--output-dir", help="Папка для сохранения результатов (создаст подпапки endpoints/, active/, secrets/)")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Количество потоков для проверки активности (по умолчанию 10)")

    args = parser.parse_args()

    urls = []

    if args.url:
        urls.append(normalize_url(args.url))

    if args.list:
        with open(args.list, "r", encoding="utf-8") as f:
            urls.extend(normalize_url(line.strip()) for line in f if line.strip())

    if not urls:
        parser.error("Нужно указать хотя бы -u или -l")

    # Если указан output-dir, подготовим папки
    if args.output_dir:
        output_dirs = prepare_output_dirs(args.output_dir)
    else:
        # По умолчанию результаты в текущей папке без подпапок
        output_dirs = {
            "endpoints": ".",
            "active": ".",
            "secrets": "."
        }

    for source in urls:
        print(f"\n[+] Идёт сканирование: {source}")
        try:
            js_code = get_js_content(source)

            base_url = args.base
            if not base_url and source.startswith(("http://", "https://")):
                base_url = get_base_url(source)

            # Декодируем закодированные строки и добавляем к исходному коду
            decoded_strings = decode_encoded_strings(js_code)
            combined_code = js_code + "\n" + "\n".join(decoded_strings)

            endpoints = extract_endpoints(combined_code, base_url)
            secrets = find_secrets(combined_code)

            if endpoints:
                print(f"[+] Найдено {len(endpoints)} эндпоинтов:")
                for ep in sorted(endpoints):
                    print(ep)

                with open(os.path.join(output_dirs["endpoints"], "endpoints.txt"), "a", encoding="utf-8") as f:
                    for ep in sorted(endpoints):
                        f.write(ep + "\n")
                print(f"[+] Эндпоинты сохранены в {os.path.join(output_dirs['endpoints'], 'endpoints.txt')}")
            else:
                print("[-] Эндпоинтов не найдено.")

            if secrets:
                print(f"[+] Найдено {len(secrets)} секретов:")
                for secret in sorted(secrets):
                    print(secret)

                with open(os.path.join(output_dirs["secrets"], "secrets.txt"), "a", encoding="utf-8") as f:
                    for secret in sorted(secrets):
                        f.write(secret + "\n")
                print(f"[+] Секреты сохранены в {os.path.join(output_dirs['secrets'], 'secrets.txt')}")
            else:
                print("[-] Секретов не найдено.")

            if args.active and endpoints:
                print(f"[+] Проверяем активность эндпоинтов (потоки: {args.threads})...")
                active_endpoints = set()
                with ThreadPoolExecutor(max_workers=args.threads) as executor:
                    futures = {executor.submit(check_endpoint_active, ep): ep for ep in endpoints}
                    for future in as_completed(futures):
                        result = future.result()
                        if result:
                            active_endpoints.add(result)

                if active_endpoints:
                    print(f"[+] Активных эндпоинтов найдено: {len(active_endpoints)}")
                    with open(os.path.join(output_dirs["active"], "active_endpoints.txt"), "a", encoding="utf-8") as f:
                        for ep in sorted(active_endpoints):
                            f.write(ep + "\n")
                    print(f"[+] Активные эндпоинты сохранены в {os.path.join(output_dirs['active'], 'active_endpoints.txt')}")
                else:
                    print("[-] Активных эндпоинтов не найдено.")

        except Exception as e:
            print(f"[-] Ошибка при обработке {source}: {e}")


if __name__ == "__main__":
    main()
