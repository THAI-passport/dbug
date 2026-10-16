# Mobile Application Privacy & Data Leakage Audit

- **Target Package:** `com.example.malware`
- **Overall Privacy Risk:** **CRITICAL**
- **Trackers Identified:** 0
- **Confirmed PII Disclosures:** 5

---

## 1. Executive Summary & Regulatory Impact
Dynamic zero-trace observation monitored all egress network communications initiated by `com.example.malware`.
Synthetic canary credentials (contacts, SMS OTPs, and clipboard buffers) were tracked out-of-band across TLS tunnels.

> [!CAUTION]
> **CRITICAL DATA EXFILTRATION DETECTED:** This application exfiltrates user PII to third-party advertising SDKs without explicit consent, representing potential violations under **GDPR Article 5(1)(c) (Data Minimization)** and **CCPA/CPRA Consumer Notice Requirements**.

---

## 2. Identified Third-Party Tracking & Advertising SDKs
| Tracking Network | Entity | Category | Risk Rating | Requests | Observed Endpoints |
| :--- | :--- | :--- | :--- | :--- | :--- |
| None Identified | N/A | clean | LOW | 0 | None |

---

## 3. Disclosed PII & Sensitive Canary Leakage
| Severity | Data Category | Canary Token | Encoding | Destination Entity | Remote Endpoint |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **HIGH** | `banking_otp` | `CANARY_SMS_OTP_9921` | `raw` | External Infrastructure | `` |
| **HIGH** | `banking_otp` | `CANARY_SMS_OTP_9921` | `hex` | External Infrastructure | `` |
| **HIGH** | `crypto_wallets` | `CANARY_WALLET_ALPHA` | `raw` | External Infrastructure | `198.51.100.24:8443` |
| **HIGH** | `banking_otp` | `CANARY_SMS_OTP_9921` | `raw` | External Infrastructure | `198.51.100.24:8443` |
| **HIGH** | `clipboard` | `CANARY_CLIPBOARD_CARD` | `raw` | External Infrastructure | `149.154.167.220:443` |

---

## 4. First-Party vs Third-Party Domain Inventory
- **First-Party / Backend Domains:** api.telegram.org, c2-api.malicious-gate.example
- **Total Distinct Domains Contacted:** 2
