
# ===============================
# Importing Libraries
# ===============================

import requests
import sys
from argparse import ArgumentParser
from urllib.parse import urlparse


# ===============================
# ANSI Color Codes
# ===============================

RED     = "\033[31m"
GREEN   = "\033[32m"
YELLOW  = "\033[33m"
CYAN    = "\033[36m"
RESET   = "\033[0m"
BOLD    = "\033[1m"


# ===============================
# Security Headers List
# ===============================

SECURITY_HEADERS = [

    # Core Security
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",

    # CORS
    "Access-Control-Allow-Origin",
    "Access-Control-Allow-Credentials",
    "Access-Control-Allow-Methods",
    "Access-Control-Allow-Headers",

    # Legacy
    "X-XSS-Protection",
    "Public-Key-Pins",
    "Expect-CT",

    # Browser Protections
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Embedder-Policy",
    "Cross-Origin-Resource-Policy",

    # Cache
    "Cache-Control",
    "Pragma",
    "Expires",

    # Cookie
    "Set-Cookie",

    # Server Disclosure
    "Server",
    "X-Powered-By",

    # Misc
    "Feature-Policy",
    "Clear-Site-Data",
    "NEL",
    "Report-To"
]


# ===============================
# URL Validation Function
# ===============================

def validate_url(url):
    """
    Validate if URL contains scheme and netloc
    """

    parsed = urlparse(url)

    if not parsed.scheme or not parsed.netloc:
        print(f"{RED}❌ Invalid URL! Example: https://example.com{RESET}")
        sys.exit(1)

    return True


# ===============================
# Security Analyzer Function
# ===============================

def security_analyzer(url):

    try:
        print(f"\n{CYAN}[*] Sending request to {url} ...{RESET}")

        response = requests.get(url, timeout=5)

        print(f"{GREEN}✔ Status Code: {response.status_code}{RESET}\n")

        # Normalize headers (lowercase for comparison)
        normalized_headers = {}

        for key, value in response.headers.items():
            normalized_headers[key.lower()] = value

        print(f"{BOLD}{CYAN}🛡️  Security Header Analysis:{RESET}\n")

        present_count = 0
        missing_count = 0

        for header in SECURITY_HEADERS:

            if header.lower() in normalized_headers:
                print(f"{GREEN}✔ {header} → Present{RESET}")
                present_count += 1
            else:
                print(f"{RED}✘ {header} → Missing{RESET}")
                missing_count += 1

        # Summary
        print(f"\n{YELLOW}📊 Summary:{RESET}")
        print(f"{GREEN}Present: {present_count}{RESET}")
        print(f"{RED}Missing: {missing_count}{RESET}")

    except requests.exceptions.RequestException as err:
        print(f"{RED}❌ Request Error: {err}{RESET}")
        sys.exit(1)


# ===============================
# Main Function
# ===============================

if __name__ == "__main__":

    parser = ArgumentParser(description="Mini Security Header Analyzer")
    parser.add_argument("-u", "--url",
                        dest="url",
                        metavar="TARGET_URL",
                        required=True,
                        help="Target URL (Example: https://example.com)")

    args = parser.parse_args()

    validate_url(args.url)
    security_analyzer(args.url)
