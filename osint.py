#!/usr/bin/env python3
import argparse
import requests
import json
from datetime import datetime
import sys
import os
import sqlite3
from bs4 import BeautifulSoup

API_KEYS = {
    'hunterio': os.getenv('HUNTERIO_API_KEY', ''),
    'hibp': os.getenv('HIBP_API_KEY', '')
}

DB_PATH = "osint_data.db"

class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# ----------------- DATABASE -------------------
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS reports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT,
                    result TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )''')
    conn.commit()
    conn.close()

def save_report(target, result):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("INSERT INTO reports (target, result) VALUES (?, ?)", (target, result))
    conn.commit()
    conn.close()

# ----------------- CHECK FUNCTIONS -------------------
def check_haveibeenpwned(email):
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
    headers = {"hibp-api-key": API_KEYS['hibp']} if API_KEYS['hibp'] else {}
    result = []
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            breaches = response.json()
            print(f"{Colors.FAIL}\n[!] Found in {len(breaches)} breaches:{Colors.ENDC}")
            for breach in breaches:
                breach_info = f"- {breach['Name']} ({breach['BreachDate']}) | Data: {', '.join(breach['DataClasses'])}"
                print(breach_info)
                result.append(breach_info)
        elif response.status_code == 404:
            print(f"{Colors.OKGREEN}\n[+] No breaches found{Colors.ENDC}")
            result.append("No breaches found")
        else:
            print(f"{Colors.WARNING}\n[?] HIBP API error: {response.status_code}{Colors.ENDC}")
            result.append("HIBP API error")
    except Exception as e:
        print(f"{Colors.WARNING}\n[?] HIBP error: {str(e)}{Colors.ENDC}")
        result.append(str(e))
    save_report(email, '\n'.join(result))


def check_hunterio(email):
    if not API_KEYS['hunterio']:
        print(f"{Colors.WARNING}\n[?] Hunter.io API key not configured{Colors.ENDC}")
        return

    url = f"https://api.hunter.io/v2/email-verifier?email={email}&api_key={API_KEYS['hunterio']}"
    result = []
    try:
        response = requests.get(url)
        data = response.json()
        if data.get('data'):
            print(f"{Colors.OKBLUE}\n[+] Hunter.io results:{Colors.ENDC}")
            print(f"Status: {data['data']['status']}")
            print(f"Disposable: {'Yes' if data['data']['disposable'] else 'No'}")
            print(f"Webmail: {'Yes' if data['data']['webmail'] else 'No'}")
            result.append(f"Status: {data['data']['status']}")
            if data['data']['sources']:
                result.append("Sources:")
                for source in data['data']['sources']:
                    source_info = f"- {source['domain']} ({source['uri']})"
                    print(source_info)
                    result.append(source_info)
    except Exception as e:
        print(f"{Colors.WARNING}\n[?] Hunter.io error: {str(e)}{Colors.ENDC}")
        result.append(str(e))
    save_report(email, '\n'.join(result))


def check_username(username):
    sites = {
        'GitHub': f'https://github.com/{username}',
        'Twitter': f'https://twitter.com/{username}',
        'Instagram': f'https://instagram.com/{username}',
        'Reddit': f'https://reddit.com/user/{username}',
        'VK': f'https://vk.com/{username}'
    }
    print(f"{Colors.OKBLUE}\n[+] Checking username {username} on social media:{Colors.ENDC}")
    result = []
    for site, url in sites.items():
        try:
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                msg = f"[+] Found on {site}: {url}"
                print(f"{Colors.OKGREEN}{msg}{Colors.ENDC}")
                result.append(msg)
        except:
            result.append(f"Error checking {site}")
    save_report(username, '\n'.join(result))

# ----------------- MAIN -------------------
def main():
    init_db()
    banner = f"""
{Colors.BOLD}{Colors.FAIL}
 __        __   _     ____                  _ _ _ 
 \ \      / /__| |__ |  _ \ __ _ _ __   ___| | | |
  \ \ /\ / / _ \ '_ \| |_) / _` | '_ \ / _ \ | | |
   \ V  V /  __/ |_) |  __/ (_| | | | |  __/ |_|_|
    \_/\_/ \___|_.__/|_|   \__,_|_| |_|\___|_(_|_)

               by webrrotkit
{Colors.ENDC}
"""
    print(banner)
    while True:
        print(f"{Colors.HEADER}\nOSINT Tool - Menu{Colors.ENDC}")
        print("1. Пробив по Email")
        print("2. Пробив по Username")
        print("3. Пробив по Telegram ID (в разработке)")
        print("4. Пробив по номеру телефона (в разработке)")
        print("5. Выход")

        choice = input("\nВыберите действие (1-5): ")

        if choice == '1':
            email = input("Введите email: ")
            check_haveibeenpwned(email)
            check_hunterio(email)
            username_guess = email.split('@')[0]
            check_username(username_guess)
        elif choice == '2':
            username = input("Введите username: ")
            check_username(username)
        elif choice == '3':
            print("[!] Пробив по Telegram ID будет добавлен позже.")
        elif choice == '4':
            print("[!] Пробив по номеру телефона будет добавлен позже.")
        elif choice == '5':
            print("Выход...")
            break
        else:
            print("Неверный выбор.")

        input(f"\n{Colors.BOLD}Нажмите Enter, чтобы продолжить...{Colors.ENDC}\n")

if __name__ == '__main__':
    main()

