# Static Malware Triage & Anti-Analysis Audit (Gate G0)

- **Target Sample:** `sample.apk`
- **SHA-256:** `2636716e970a50e45f957a71d05f9e8f413367305528c5965a8a4c1f293a13b0`
- **MD5:** `d41d8cd98f00b204e9800998ecf8427e`
- **File Size:** 4582910 bytes

---

## 1. Packer & Architecture Profile
- **Detected Packers:** None detected (Unpacked)
- **Native Libraries:** 1 detected (libnative-crypto.so)

---

## 2. High-Risk Permissions & Capabilities

- `android.permission.BIND_ACCESSIBILITY_SERVICE`: Critical infostealer/RAT indicator `[C]`
- `android.permission.SYSTEM_ALERT_WINDOW`: Critical infostealer/RAT indicator `[C]`
- `android.permission.READ_SMS`: Critical infostealer/RAT indicator `[C]`
- `android.permission.RECEIVE_SMS`: Critical infostealer/RAT indicator `[C]`
- `android.permission.QUERY_ALL_PACKAGES`: Critical infostealer/RAT indicator `[C]`

---

## 3. Detected Anti-Analysis & Evasion Cues
The sample statically references the following environment detection artifacts `[C]`:
- `adb_enabled`: Countermeasure required prior to dynamic spawn.
- `development_settings_enabled`: Countermeasure required prior to dynamic spawn.
- `ro.debuggable`: Countermeasure required prior to dynamic spawn.
- `sys.usb.state`: Countermeasure required prior to dynamic spawn.
- `TracerPid`: Countermeasure required prior to dynamic spawn.
- `tun0`: Countermeasure required prior to dynamic spawn.
- `http.proxyHost`: Countermeasure required prior to dynamic spawn.

---

## 4. Hardcoded C2 & Exfiltration Strings
| Type | Indicator | Evidence Tag |
| :--- | :--- | :--- |
| URL | `https://api.telegram.org/bot6829104812:AAH9fCANARYTokenMockSecretKey/sendMessage` | `[C]` |
| URL | `https://c2-api.malicious-gate.example/api/v1/gate` | `[C]` |
| IPv4 | `198.51.100.24` | `[C]` |
| Telegram Token | `6829104812:AAH9fCANARYTokenMockSecretKey` | `[C]` |
