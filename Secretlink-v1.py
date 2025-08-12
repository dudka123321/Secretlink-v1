import re
import base64
import argparse
import requests
import os
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

pattern = re.compile(
    r"""(?:"|')((?:[a-zA-Z]{1,10}://|//)[^"'\s]{1,}
    |(?:/|\.\./|\./)[^"'\s<>]{1,}
    |[a-zA-Z0-9_\-]+(?:\.[a-zA-Z]{2,})(?:/[^"'\s]*)?)["']""",
    re.VERBOSE
)

SECRET_KEYWORDS = [
    "api_key", "apikey", "api-key", "secret", "token", "auth", "password",
    "passwd", "pwd", "admin", "access_token", "auth_token", "client_secret",
    "private_key", "jwt", "sessionid", "cookie", "secret_key"
]

def normalize_url(url):
    if not url.startswith(("http://", "https://")):
        return "https://" + url
    return url

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
    found = set()
    for keyword in SECRET_KEYWORDS:
        pattern = re.compile(rf"{keyword}['\"]?\s*[:=]\s*['\"]([^'\"]+)['\"]", re.I)
        for m in pattern.findall(js_code):
            found.add(f"{keyword}: {m}")
    return found

def decode_encoded_strings(js_code):
    decoded_strings = set()
    base64_pattern = re.compile(r'([A-Za-z0-9+/=]{8,})')
    for b64 in base64_pattern.findall(js_code):
        try:
            decoded = base64.b64decode(b64).decode('utf-8')
            if len(decoded) > 4:
                decoded_strings.add(decoded)
        except Exception:
            pass

    url_encoded_pattern = re.compile(r'%[0-9a-fA-F]{2,}')
    for match in url_encoded_pattern.findall(js_code):
        try:
            decoded = requests.utils.unquote(match)
            decoded_strings.add(decoded)
        except Exception:
            pass

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

def check_endpoint_active(url):
    try:
        resp = requests.head(url, timeout=5, allow_redirects=True)
        if resp.status_code == 200:
            return url
    except Exception:
        pass
    return None

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

def prepare_output_dirs(base_dir, active_enabled):
    subfolders = ["path", "content", "static"]

    # endpoints: maindomain и otherdomain + их подкаталоги
    endpoints_base = os.path.join(base_dir, "endpoints")
    maindomain_dir = os.path.join(endpoints_base, "maindomain")
    otherdomain_dir = os.path.join(endpoints_base, "otherdomain")
    for parent in [maindomain_dir, otherdomain_dir]:
        for sf in subfolders:
            os.makedirs(os.path.join(parent, sf), exist_ok=True)

    # secrets
    secrets_dir = os.path.join(base_dir, "secrets")
    os.makedirs(secrets_dir, exist_ok=True)

    active_dirs = None
    if active_enabled:
        # active: тоже maindomain и otherdomain с подкаталогами
        active_base = os.path.join(base_dir, "active")
        active_maindomain = os.path.join(active_base, "maindomain")
        active_otherdomain = os.path.join(active_base, "otherdomain")
        for parent in [active_maindomain, active_otherdomain]:
            for sf in subfolders:
                os.makedirs(os.path.join(parent, sf), exist_ok=True)
        active_dirs = {
            "base": active_base,
            "maindomain": active_maindomain,
            "otherdomain": active_otherdomain,
            "subfolders": subfolders
        }

    return {
        "endpoints": {
            "maindomain": maindomain_dir,
            "otherdomain": otherdomain_dir,
            "subfolders": subfolders
        },
        "secrets": secrets_dir,
        "active": active_dirs
    }

def classify_endpoint(url):
    content_exts = (
        ".jpg", ".jpeg", ".png", ".svg", ".gif", ".webp", ".bmp", ".ico",
        ".tiff", ".heic", ".avif", ".mp3", ".mp4", ".pdf"
    )
    static_exts = (".html", ".htm", ".js", ".css", ".json", ".xml", ".txt")

    path = urlparse(url).path.lower()
    if path in ("", "/"):
        return "path"

    for ext in content_exts:
        if path.endswith(ext):
            return "content"

    for ext in static_exts:
        if path.endswith(ext):
            return "static"

    return "path"

def domain_type(domain, base_domain):
    return "maindomain" if domain == base_domain else "otherdomain"

def classify_and_save_endpoints(endpoints, base_domain, endpoints_dirs):
    categorized = {
        "maindomain": {sf: [] for sf in endpoints_dirs["subfolders"]},
        "otherdomain": {sf: [] for sf in endpoints_dirs["subfolders"]},
    }

    for ep in endpoints:
        dom = urlparse(ep).netloc
        d_type = domain_type(dom, base_domain)
        class_type = classify_endpoint(ep)
        categorized[d_type][class_type].append(ep)

    for d_type in ["maindomain", "otherdomain"]:
        base_path = endpoints_dirs[d_type]
        for sf in endpoints_dirs["subfolders"]:
            lst = sorted(set(categorized[d_type][sf]))
            if lst:
                file_path = os.path.join(base_path, sf, f"{sf}_endpoints.txt")
                with open(file_path, "a", encoding="utf-8") as f:
                    for line in lst:
                        f.write(line + "\n")

def save_active_endpoints(active_endpoints, base_domain, active_dirs):
    if not active_dirs:
        return

    categorized = {
        "maindomain": {sf: [] for sf in active_dirs["subfolders"]},
        "otherdomain": {sf: [] for sf in active_dirs["subfolders"]},
    }

    for ep in active_endpoints:
        dom = urlparse(ep).netloc
        d_type = domain_type(dom, base_domain)
        class_type = classify_endpoint(ep)
        categorized[d_type][class_type].append(ep)

    for d_type in ["maindomain", "otherdomain"]:
        base_path = active_dirs[d_type]
        for sf in active_dirs["subfolders"]:
            lst = sorted(set(categorized[d_type][sf]))
            if lst:
                file_path = os.path.join(base_path, sf, f"{sf}_active_endpoints.txt")
                with open(file_path, "a", encoding="utf-8") as f:
                    for line in lst:
                        f.write(line + "\n")

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

    if args.output_dir:
        output_dirs = prepare_output_dirs(args.output_dir, active_enabled=args.active)
    else:
        # создаём папки по умолчанию (упрощённо)
        output_dirs = {
            "endpoints": {
                "maindomain": "endpoints/maindomain",
                "otherdomain": "endpoints/otherdomain",
                "subfolders": ["path", "content", "static"]
            },
            "secrets": "secrets",
            "active": None
        }
        for d in [output_dirs["endpoints"]["maindomain"], output_dirs["endpoints"]["otherdomain"], output_dirs["secrets"]]:
            os.makedirs(d, exist_ok=True)
        if args.active:
            output_dirs["active"] = {
                "base": "active",
                "maindomain": os.path.join("active", "maindomain"),
                "otherdomain": os.path.join("active", "otherdomain"),
                "subfolders": ["path", "content", "static"]
            }
            for parent in [output_dirs["active"]["maindomain"], output_dirs["active"]["otherdomain"]]:
                for sf in output_dirs["active"]["subfolders"]:
                    os.makedirs(os.path.join(parent, sf), exist_ok=True)

    for source in urls:
        print(f"\n[+] Идёт сканирование: {source}")
        try:
            js_code = get_js_content(source)

            base_url = args.base
            if not base_url and source.startswith(("http://", "https://")):
                base_url = get_base_url(source)

            base_domain = urlparse(base_url).netloc if base_url else ""

            decoded_strings = decode_encoded_strings(js_code)
            combined_code = js_code + "\n" + "\n".join(decoded_strings)

            endpoints = extract_endpoints(combined_code, base_url)
            secrets = find_secrets(combined_code)

            if endpoints:
                print(f"[+] Найдено {len(endpoints)} эндпоинтов:")
                for ep in sorted(endpoints):
                    print(ep)

                classify_and_save_endpoints(endpoints, base_domain, output_dirs["endpoints"])
                print(f"[+] Эндпоинты разложены и сохранены в папках endpoints/maindomain и endpoints/otherdomain")
            else:
                print("[-] Эндпоинтов не найдено.")

            if secrets:
                print(f"[+] Найдено {len(secrets)} секретов:")
                for secret in sorted(secrets):
                    print(secret)

                with open(os.path.join(output_dirs["secrets"], "secrets.txt"), "a", encoding="utf-8") as f:
                    f.write(f"[Источник: {source}]\n")
                    for secret in sorted(secrets):
                        f.write(secret + "\n")
                    f.write("\n")
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
                    save_active_endpoints(active_endpoints, base_domain, output_dirs["active"])
                    print(f"[+] Активные эндпоинты сохранены в папках active/maindomain и active/otherdomain")
                else:
                    print("[-] Активных эндпоинтов не найдено.")

        except Exception as e:
            print(f"[-] Ошибка при обработке {source}: {e}")


if __name__ == "__main__":
    main()
