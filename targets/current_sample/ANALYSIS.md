# Dynamic Malware Analysis & Threat Intelligence Report

- **Package Name:** `com.example.malware`
- **SHA-256 Hash:** `simulated_0000000000000000000000000000000000000000000000000000000000`
- **Analysis Timestamp:** 2026-10-16 16:42:50 UTC
- **Environment:** Physical Android Hardware (Cloaked, eBPF Uprobes, Out-of-Band Gateway)

---

## 1. Executive Summary
Dynamic behavioral analysis was conducted inside the isolated `dbug` sandbox. USB debugging and system developer telemetry were masked at the kernel and `system_server` level (`ro.debuggable=0`, `sys.usb.state=mtp`, `Settings.Global.adb_enabled=0`).

**Exfiltration Determination:** [N] Data theft CONFIRMED. The malware successfully harvested and transmitted **5** seeded synthetic canary credentials across memory buffers and decrypted network sessions.

---

## 2. Command and Control (C2) Infrastructure

| Indicator | Type | Evidence Tag | Description |
| :--- | :--- | :--- | :--- |
| `149.154.167.220` | IPv4 Address | `[N]` | Active C2 Network Endpoint |
| `198.51.100.24` | IPv4 Address | `[N]` | Active C2 Network Endpoint |
| `api.telegram.org` | Domain Name | `[N]` / `[M]` | Resolved C2 Domain / Host |
| `c2-api.malicious-gate.example` | Domain Name | `[N]` / `[M]` | Resolved C2 Domain / Host |
| `6829104812:AAH9fCANARYTokenMockSecretKey` | Telegram Bot Token | `[N]` | Exfiltration Bot Endpoint |
| `https://api.telegram.org/bot6829104812:AAH9fCANARYTokenMockSecretKey/sendMessage` | Full HTTP Endpoint | `[N]` | Payload Exfiltration URI |
| `https://c2-api.malicious-gate.example/api/v1/gate` | Full HTTP Endpoint | `[N]` | Payload Exfiltration URI |

---

## 3. Cryptographic Extraction & Memory Telemetry

| Algorithm | Key Hex | IV Hex | Evidence Tag |
| :--- | :--- | :--- | :--- |
| `AES/CBC/PKCS5Padding` | `c8f1e2d3b4a5968778695a4b3c2d1e0f...` | `00112233445566778899aabbccddeeff` | `[M]` |

---

## 4. Canary Exfiltration Proof Ledger

| Evidence Tag | Channel | Canary Token | Field | Encoding | Destination |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `[M]` | MEMORY | `CANARY_SMS_OTP_9921` | otp_code | `raw` | `Cipher event: AES/CBC/PKCS5Pad` |
| `[M]` | MEMORY | `CANARY_SMS_OTP_9921` | otp_code | `hex` | `Cipher event: AES/CBC/PKCS5Pad` |
| `[N]` | NETWORK | `CANARY_WALLET_ALPHA` | address | `raw` | `198.51.100.24:8443` |
| `[N]` | NETWORK | `CANARY_SMS_OTP_9921` | otp_code | `raw` | `198.51.100.24:8443` |
| `[N]` | NETWORK | `CANARY_CLIPBOARD_CARD` | text | `raw` | `149.154.167.220:443` |

---

## 5. Defensive Recommendations & Mitigations
1. **Network Egress Blocking:** Blacklist destination IPs (`149.154.167.220, 198.51.100.24`) and resolved domains at perimeter firewalls.
2. **Token Revocation:** Revoke reported Telegram Bot tokens (1 tokens detected) via `@BotFather` abuse reporting.
3. **Canary Rotation:** Rotate mock credentials in `config/mock_canaries.json` before initiating subsequent analysis sessions.
