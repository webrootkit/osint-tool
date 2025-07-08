#!/usr/bin/env python3
import argparse
import requests
import json
from datetime import datetime
import sys
import os
from bs4 import BeautifulSoup

API_KEYS = {
    'hunterio': os.getenv('HUNTERIO_API_KEY', ''),
    'hibp': os.getenv('HIBP_API_KEY', '')
}

class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def check_haveibeenpwned(email):
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
    headers = {"hibp-api-key": API_KEYS['hibp']} if API_KEYS['hibp'] else {}
    
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            breaches = response.json()
            print(f"{Colors.FAIL}\n[!] Found in {len(breaches)} breaches:{Colors.ENDC}")
            for breach in breaches:
                print(f"- {breach['Name']} ({breach['BreachDate']})")
                print(f"  Data leaked: {', '.join(breach['DataClasses'])}")
        elif response.status_code == 404:
            print(f"{Colors.OKGREEN}\n[+] No breaches found{Colors.ENDC}")
        else:
            print(f"{Colors.WARNING}\n[?] HIBP API error: {response.status_code}{Colors.ENDC}")
    except Exception as e:
        print(f"{Colors.WARNING}\n[?] HIBP error: {str(e)}{Colors.ENDC}")

def check_hunterio(email):
    if not API_KEYS['hunterio']:
        print(f"{Colors.WARNING}\n[?] Hunter.io API key not configured{Colors.ENDC}")
        return
    
    url = f"https://api.hunter.io/v2/email-verifier?email={email}&api_key={API_KEYS['hunterio']}"
    
    try:
        response = requests.get(url)
        data = response.json()
        if data.get('data'):
            print(f"{Colors.OKBLUE}\n[+] Hunter.io results:{Colors.ENDC}")
            print(f"Status: {data['data']['status']}")
            print(f"Disposable: {'Yes' if data['data']['disposable'] else 'No'}")
            print(f"Webmail: {'Yes' if data['data']['webmail'] else 'No'}")
            if data['data']['sources']:
                print("Found on:")
                for source in data['data']['sources']:
                    print(f"- {source['domain']} ({source['uri']})")
    except Exception as e:
        print(f"{Colors.WARNING}\n[?] Hunter.io error: {str(e)}{Colors.ENDC}")

def check_username(username):
    sites = {
        'GitHub': f'https://github.com/{username}',
        'Twitter': f'https://twitter.com/{username}',
        'Instagram': f'https://instagram.com/{username}',
        'Reddit': f'https://reddit.com/user/{username}',
        'VK': f'https://vk.com/{username}'
    }
    
    print(f"{Colors.OKBLUE}\n[+] Checking username {username} on social media:{Colors.ENDC}")
    
    for site, url in sites.items():
        try:
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                print(f"{Colors.OKGREEN}[+] Found on {site}: {url}{Colors.ENDC}")
            elif response.status_code == 404:
                pass
            else:
                print(f"{Colors.WARNING}[?] {site} returned {response.status_code}{Colors.ENDC}")
        except:
            print(f"{Colors.WARNING}[?] Error checking {site}{Colors.ENDC}")

def main():
    parser = argparse.ArgumentParser(description='OSINT information gathering tool')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--email', help='Email address to investigate')
    group.add_argument('--username', help='Username to investigate')
    args = parser.parse_args()
    
    print(f"{Colors.HEADER}\nOSINT Tool - Starting investigation{Colors.ENDC}")
    print(f"{Colors.UNDERLINE}Report generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.ENDC}")
    
    if args.email:
        check_haveibeenpwned(args.email)
        check_hunterio(args.email)
        username = args.email.split('@')[0]
        check_username(username)
    
    if args.username:
        check_username(args.username)

if __name__ == '__main__':
    main()