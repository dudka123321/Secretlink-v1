import re
import base64
import argparse
import requests
import codecs
import binascii
import urllib.parse
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

def print_logo():
    logo = r"""
   _____                     _    _ _       
  / ____|                   | |  | (_)      
 | (___  _   _ _ __ ___ ___ | |  | |_  __ _ 
  \___ \| | | | '__/ __/ _ \| |  | | |/ _` |
  ____) | |_| | | | (_| (_) | |__| | | (_| |
 |_____/ \__,_|_|  \___\___/ \____/|_|\__,_|

    SecretLink - JS Endpoint & Secret Extractor
    """
    print(logo)

# Регулярка для поиска URL и путей в JS коде
pattern = re.compile(
    r"""(?:"|')((?:[a-zA-Z]{1,10}://|//)[^"'\s]{1,}
    |(?:/|\.\./|\./)[^"'\s<>]{1,}
    |[a-zA-Z0-9_\-]+(?:\.[a-zA-Z]{2,})(?:/[^"'\s]*)?)["']""",
    re.VERBOSE
)

# Регулярка для поиска base64-строк (классический вариант)
base64_pattern = re.compile(r'[A-Za-z0-9+/]{20,}={0,2}')

# Регулярка для поиска hex-строк (минимум 20 символов)
hex_pattern = re.compile(r'\b[0-9a-fA-F]{20,}\b')

# Регулярка для поиска URL-кодированных строк (содержат %)
urlencoded_pattern = re.compile(r'%[0-9A-Fa-f]{2,}[%0-9A-Fa-f]*')

# Ключевые слова для поиска секретов
SECRET_KEYWORDS = [
    "api_key", "apikey", "api-key", "secret", "token", "auth", "passwd", "password",
    "access_token", "session", "credentials", "key", "jwt", "admin", "authorization",
    "secret_key", "client_secret", "private_key", "db_password", "auth_token"
]

# Кеш для проверки активности
active_check_cache = {}
cache_lock = threading.Lock()

def normalize_url(url):
    if not url.startswith(("http://", "https://")):
        return "https://" + url
    return url

def get_js_content(source):
    if not source.startswith("http") and ("/" in source or "." in source):
        source = "https://" + source

    if source.startswith("http"):
        resp = requests.get(source, timeout=10)
        resp.raise_for_status()
        return resp.text
    else:
        with open(source, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()

def extract_endpoints(js_code, base_url=None):
    matches = re.findall(pattern, js_code)
    results = set()
    for match in matches:
        if base_url:
            results.add(urljoin(base_url, match))
        else:
            results.add(match)
    return results

def get_base_url(url):
    parsed = urlparse(url)
    path = parsed.path
    if "/" in path:
        path = path.rsplit("/", 1)[0] + "/"
    else:
        path = "/"
    base = f"{parsed.scheme}://{parsed.netloc}{path}"
    return base

def find_secrets(js_code):
    secrets_found = set()
    lower_text = js_code.lower()
    for key in SECRET_KEYWORDS:
        # Ищем ключевые слова с контекстом +/- 50 символов
        for match in re.finditer(r'(?i)(.{0,50}' + re.escape(key) + r'.{0,50})', lower_text):
            snippet = js_code[match.start():match.end()]
            # Ищем в snippet строковые значения (в кавычках)
            secret_matches = re.findall(r'(?:"|\')([A-Za-z0-9_\-+=/]{8,})["\']', snippet)
            secrets_found.update(secret_matches)
    return secrets_found

def try_base64_decode(s):
    try:
        # Пытаемся декодировать base64 и получить utf-8 строку
        decoded_bytes = base64.b64decode(s, validate=True)
        decoded_text = decoded_bytes.decode('utf-8', errors='ignore')
        return decoded_text if decoded_text else None
    except Exception:
        return None

def try_hex_decode(s):
    try:
        decoded_bytes = binascii.unhexlify(s)
        decoded_text = decoded_bytes.decode('utf-8', errors='ignore')
        return decoded_text if decoded_text else None
    except Exception:
        return None

def try_url_decode(s):
    try:
        decoded = urllib.parse.unquote(s)
        return decoded if decoded != s else None
    except Exception:
        return None

def try_rot13_decode(s):
    try:
        return s.encode('rot_13').decode('utf-8')
    except Exception:
        # В Python3 лучше так:
        return codecs.decode(s, 'rot_13')

def extract_encoded_strings(js_code):
    # Находим возможные base64, hex, urlencoded подстроки
    base64s = base64_pattern.findall(js_code)
    hexs = hex_pattern.findall(js_code)
    urlencs = urlencoded_pattern.findall(js_code)
    return base64s, hexs, urlencs

def print_progress(iteration, total, prefix='', suffix='', decimals=1, bar_length=30):
    percent = f"{100 * (iteration / float(total)):.{decimals}f}"
    filled_length = int(bar_length * iteration // total)
    bar = '█' * filled_length + '-' * (bar_length - filled_length)
    print(f'\r{prefix} |{bar}| {percent}% {suffix}', end='')
    if iteration == total:
        print()

def check_url_active(url, timeout=5):
    with cache_lock:
        if url in active_check_cache:
            return active_check_cache[url]
    try:
        resp = requests.head(url, allow_redirects=True, timeout=timeout)
        active = resp.status_code < 400
    except Exception:
        active = False
    with cache_lock:
        active_check_cache[url] = active
    return active

def check_active_endpoints(endpoints, max_workers=10):
    active_eps = set()
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_url = {executor.submit(check_url_active, url): url for url in endpoints}
        total = len(endpoints)
        for i, future in enumerate(as_completed(future_to_url), 1):
            url = future_to_url[future]
            print_progress(i, total, prefix='Проверка эндпоинтов:', suffix=f'{i}/{total}')
            try:
                if future.result():
                    active_eps.add(url)
            except Exception:
                pass
    return active_eps

def decode_all_variants(js_code):
    decoded_chunks = []

    base64s, hexs, urlencs = extract_encoded_strings(js_code)

    # Base64 decode
    for s in base64s:
        d = try_base64_decode(s)
        if d:
            decoded_chunks.append(d)

    # Hex decode
    for s in hexs:
        d = try_hex_decode(s)
        if d:
            decoded_chunks.append(d)

    # URL decode
    for s in urlencs:
        d = try_url_decode(s)
        if d:
            decoded_chunks.append(d)

    # ROT13 decode (проверим весь текст)
    try:
        import codecs
        rot13_decoded = codecs.decode(js_code, 'rot_13')
        if rot13_decoded and rot13_decoded != js_code:
            decoded_chunks.append(rot13_decoded)
    except Exception:
        pass

    return decoded_chunks


def main():
    parser = argparse.ArgumentParser(
        description="SecretLink — Extract endpoints and secrets from JS files/URLs",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("-u", "--url", help="Один URL или локальный файл для сканирования")
    parser.add_argument("-l", "--list", help="Файл со списком URL или путей для сканирования")
    parser.add_argument("-b", "--base", help="Базовый URL для относительных путей")
    parser.add_argument("-a", "--active", action="store_true", help="Проверять найденные эндпоинты на активность")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Количество потоков для проверки активности (по умолчанию 10)")
    args = parser.parse_args()

    print_logo()

    urls = []
    if args.url:
        urls.append(normalize_url(args.url))
    if args.list:
        with open(args.list, "r", encoding="utf-8") as f:
            urls.extend(normalize_url(line.strip()) for line in f if line.strip())

    if not urls:
        parser.error("Нужно указать хотя бы -u или -l")

    all_endpoints = set()
    all_secrets = set()

    for i, source in enumerate(urls, 1):
        print(f"\n[{i}/{len(urls)}] Сканирование: {source}")
        try:
            js_code = get_js_content(source)

            base_url = args.base
            if not base_url and source.startswith(("http://", "https://")):
                base_url = get_base_url(source)

            # Получаем все варианты декодированных данных
            decoded_chunks = decode_all_variants(js_code)

            # Объединяем исходный код и все декодированные варианты
            combined_text = "\n".join([js_code] + decoded_chunks)

            endpoints = extract_endpoints(combined_text, base_url)
            secrets = find_secrets(combined_text)

            all_endpoints.update(endpoints)
            all_secrets.update(secrets)

            print(f"[+] Найдено эндпоинтов: {len(endpoints)}")
            print(f"[+] Найдено потенциальных секретов: {len(secrets)}")

        except Exception as e:
            print(f"[-] Ошибка при обработке {source}: {e}")

    # Записываем результаты
    if all_endpoints:
        with open("endpoints.txt", "w", encoding="utf-8") as f:
            for ep in sorted(all_endpoints):
                f.write(ep + "\n")
        print("[+] Эндпоинты сохранены в endpoints.txt")
    else:
        print("[-] Эндпоинтов не найдено.")

    if all_secrets:
        with open("secrets.txt", "w", encoding="utf-8") as f:
            for secret in sorted(all_secrets):
                f.write(secret + "\n")
        print("[+] Секреты сохранены в secrets.txt")
    else:
        print("[-] Секретов не найдено.")

    # Если включена проверка активности - запускаем многопоточную проверку
    if args.active and all_endpoints:
        print("\n=== Проверка активности эндпоинтов ===")
        active_eps = check_active_endpoints(all_endpoints, max_workers=args.threads)
        if active_eps:
            with open("active_endpoints.txt", "w", encoding="utf-8") as f:
                for ep in sorted(active_eps):
                    f.write(ep + "\n")
            print(f"[+] Активных эндпоинтов: {len(active_eps)} (сохранены в active_endpoints.txt)")
        else:
            print("[-] Активных эндпоинтов не найдено.")

if __name__ == "__main__":
    main()
