#!/usr/bin/env python3
"""build_samples.py: Generates defensive mock test samples for dbug.

Produces:
1. samples/sample.apk: Valid Android APK containing DEX, manifest, and AArch64 .so
2. samples/sample_arm64.elf: Valid AArch64 ELF standalone executable
3. samples/sample_x86_64.elf: Valid x86_64 ELF standalone executable

All samples are defensive mock binaries containing synthetic canary markers,
tracker endpoints, and obfuscated string decryption routines for testing
and immediate out-of-the-box analysis without physical hardware.
"""

import hashlib
import os
import struct
import zipfile


def make_minimal_dex():
    """Constructs a syntactically valid DEX file (v035) with embedded strings."""
    # Embedded strings for static triage, tracker detection, and API spec generation
    strings = [
        "Lcom/example/malware/MainActivity;",
        "Lcom/example/malware/C2Service;",
        "android.permission.INTERNET",
        "android.permission.READ_SMS",
        "android.permission.READ_CONTACTS",
        "https://api.telegram.org/bot6829104812:AAH9fCANARYTokenMockSecretKey/sendMessage",
        "http://c2-tracker.threat-intel-example.org/api/v1/gate",
        "https://graph.facebook.com/v16.0/act_99182/adspixels",
        "https://app.appsflyer.com/com.example.malware?idfa=00000000",
        "https://api2.amplitude.com/2/httpapi",
        "https://api.example.com/api/v1/auth/login",
        "https://api.example.com/api/v1/user/profile",
        "https://api.example.com/api/v1/wallet/transfer",
        "CANARY_SMS_OTP_9921",
        "AES/CBC/PKCS5Padding",
        "AES",
        "libpayload.so",
        "Java_com_example_malware_NativePayload_decryptC2",
        "init",
        "doFinal",
        "connect"
    ]

    # Deduplicate and sort strings per DEX format
    unique_strings = sorted(list(set(strings)))
    num_strings = len(unique_strings)

    # Build String Data
    string_data_bytes = bytearray()
    string_data_offsets = []

    for s in unique_strings:
        string_data_offsets.append(len(string_data_bytes))
        # MUTF-8 length (ULEB128) followed by utf-8 bytes and null terminator
        utf8_bytes = s.encode("utf-8")
        # For len < 128, length is single byte
        string_data_bytes.append(len(utf8_bytes))
        string_data_bytes.extend(utf8_bytes)
        string_data_bytes.append(0)

    # Base offsets
    header_size = 0x70
    string_ids_offset = header_size
    string_ids_size = num_strings * 4
    string_data_start = string_ids_offset + string_ids_size

    # Build String IDs
    string_ids_bytes = bytearray()
    for off in string_data_offsets:
        string_ids_bytes.extend(struct.pack("<I", string_data_start + off))

    file_size = string_data_start + len(string_data_bytes)

    # Assemble header (DEX 035)
    header = bytearray(header_size)
    # Magic: dex\n035\0
    header[0:8] = b"dex\n035\x00"
    # Checksum and signature will be computed
    # File size
    struct.pack_into("<I", header, 0x20, file_size)
    # Header size
    struct.pack_into("<I", header, 0x24, header_size)
    # Endian tag (0x12345678)
    struct.pack_into("<I", header, 0x28, 0x12345678)
    # String IDs
    struct.pack_into("<I", header, 0x38, num_strings)
    struct.pack_into("<I", header, 0x3C, string_ids_offset)

    full_dex = header + string_ids_bytes + string_data_bytes

    # Compute SHA-1 signature (bytes 0x0c to 0x20)
    sha1 = hashlib.sha1(full_dex[0x20:]).digest()
    full_dex[0x0C:0x20] = sha1

    # Compute Adler-32 checksum (bytes 0x08 to 0x0c)
    import zlib
    adler = zlib.adler32(full_dex[0x0C:]) & 0xFFFFFFFF
    struct.pack_into("<I", full_dex, 0x08, adler)

    return bytes(full_dex)


def make_arm64_elf_so():
    """Creates a valid AArch64 ELF shared object (.so) with exported symbols."""
    # ELF Header (64-bit, LSB, ARM AArch64)
    e_ident = bytearray(16)
    e_ident[0:4] = b"\x7fELF"
    e_ident[4] = 2  # 64-bit
    e_ident[5] = 1  # 2's complement, little endian
    e_ident[6] = 1  # Current version
    e_ident[7] = 0  # System V ABI
    e_ident[8] = 0  # ABI Version

    e_type = 3       # ET_DYN (Shared object)
    e_machine = 183  # EM_AARCH64
    e_version = 1
    e_entry = 0x1000
    e_phoff = 64     # Immediately following ELF header
    e_shoff = 0      # No section headers needed for runtime
    e_flags = 0
    e_ehsize = 64
    e_phentsize = 56
    e_phnum = 1
    e_shentsize = 64
    e_shnum = 0
    e_shstrndx = 0

    ehdr = struct.pack(
        "<16sHHIQQQIHHHHHH",
        bytes(e_ident), e_type, e_machine, e_version,
        e_entry, e_phoff, e_shoff, e_flags,
        e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx
    )

    # Program Header: PT_LOAD
    p_type = 1       # PT_LOAD
    p_flags = 7      # RWX
    p_offset = 0
    p_vaddr = 0x10000000
    p_paddr = 0x10000000
    p_filesz = 0x1000
    p_memsz = 0x1000
    p_align = 0x1000

    phdr = struct.pack(
        "<IIQQQQQQ",
        p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align
    )

    # Code / String payload
    # Exported symbol names and decrypted C2 string
    c2_plaintext = b"https://api.telegram.org/bot6829104812:AAH9fCANARYTokenMockSecretKey/sendMessage"
    xor_key = 0x5A
    encrypted_c2 = bytes([b ^ xor_key for b in c2_plaintext])

    body = bytearray(0x1000 - len(ehdr) - len(phdr))
    # Place symbol markers
    sym_blob = b"Java_com_example_malware_NativePayload_decryptC2\x00JNI_OnLoad\x00"
    body[0:len(sym_blob)] = sym_blob
    body[100:100 + len(encrypted_c2)] = encrypted_c2

    # AArch64 instruction bytes for a simple XOR loop:
    # 0: e0 03 00 aa  mov x0, x0
    # 4: c0 03 5f d6  ret
    instrs = b"\xe0\x03\x00\xaa\xc0\x03\x5f\xd6"
    body[200:200 + len(instrs)] = instrs

    return ehdr + phdr + bytes(body)


def make_arm64_elf_executable():
    """Creates a valid standalone AArch64 ELF executable."""
    e_ident = bytearray(16)
    e_ident[0:4] = b"\x7fELF"
    e_ident[4] = 2  # 64-bit
    e_ident[5] = 1  # Little endian
    e_ident[6] = 1  # Current version

    e_type = 2       # ET_EXEC
    e_machine = 183  # EM_AARCH64
    e_version = 1
    e_entry = 0x400080
    e_phoff = 64
    e_shoff = 0
    e_flags = 0
    e_ehsize = 64
    e_phentsize = 56
    e_phnum = 1
    e_shentsize = 64
    e_shnum = 0
    e_shstrndx = 0

    ehdr = struct.pack(
        "<16sHHIQQQIHHHHHH",
        bytes(e_ident), e_type, e_machine, e_version,
        e_entry, e_phoff, e_shoff, e_flags,
        e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx
    )

    phdr = struct.pack(
        "<IIQQQQQQ",
        1, 7, 0, 0x400000, 0x400000, 0x1000, 0x1000, 0x1000
    )

    body = bytearray(0x1000 - len(ehdr) - len(phdr))
    # Embedded strings and AArch64 code
    c2_plaintext = b"https://api.telegram.org/bot6829104812:AAH9fCANARYTokenMockSecretKey/sendMessage\x00CANARY_OTP_849201\x00"
    xor_key = 0x5A
    enc = bytes([b ^ xor_key for b in c2_plaintext])

    body[0:len(enc)] = enc
    # AArch64 instructions: mov x0, 0; ret
    body[0x80:0x88] = b"\x00\x00\x80\xd2\xc0\x03\x5f\xd6"

    return ehdr + phdr + bytes(body)


def make_x86_64_elf_executable():
    """Creates a valid standalone x86_64 ELF executable."""
    e_ident = bytearray(16)
    e_ident[0:4] = b"\x7fELF"
    e_ident[4] = 2  # 64-bit
    e_ident[5] = 1  # Little endian
    e_ident[6] = 1  # Current version

    e_type = 2       # ET_EXEC
    e_machine = 62   # EM_X86_64
    e_version = 1
    e_entry = 0x400080
    e_phoff = 64
    e_shoff = 0
    e_flags = 0
    e_ehsize = 64
    e_phentsize = 56
    e_phnum = 1
    e_shentsize = 64
    e_shnum = 0
    e_shstrndx = 0

    ehdr = struct.pack(
        "<16sHHIQQQIHHHHHH",
        bytes(e_ident), e_type, e_machine, e_version,
        e_entry, e_phoff, e_shoff, e_flags,
        e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx
    )

    phdr = struct.pack(
        "<IIQQQQQQ",
        1, 7, 0, 0x400000, 0x400000, 0x1000, 0x1000, 0x1000
    )

    body = bytearray(0x1000 - len(ehdr) - len(phdr))
    # Embedded strings and x86_64 code
    c2_plaintext = b"https://api.telegram.org/bot6829104812:AAH9fCANARYTokenMockSecretKey/sendMessage\x00CANARY_OTP_849201\x00"
    xor_key = 0x5A
    enc = bytes([b ^ xor_key for b in c2_plaintext])

    body[0:len(enc)] = enc
    # x86_64 instructions: xor eax, eax; ret (31 c0 c3)
    body[0x80:0x83] = b"\x31\xc0\xc3"

    return ehdr + phdr + bytes(body)


def build_sample_apk(output_path="samples/sample.apk"):
    """Packages a complete defensive mock APK."""
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    manifest_xml = b"""<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.malware"
    android:versionCode="1"
    android:versionName="1.0">
    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.READ_SMS" />
    <uses-permission android:name="android.permission.READ_CONTACTS" />
    <application android:label="MockSample" android:debuggable="false">
        <activity android:name="com.example.malware.MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
        <service android:name="com.example.malware.C2Service" />
    </application>
</manifest>"""

    dex_data = make_minimal_dex()
    arm64_so = make_arm64_elf_so()

    with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("AndroidManifest.xml", manifest_xml)
        z.writestr("classes.dex", dex_data)
        z.writestr("lib/arm64-v8a/libpayload.so", arm64_so)
        z.writestr("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\r\nCreated-By: dbug\r\n")

    print(f"[+] Built sample APK: {output_path} ({os.path.getsize(output_path)} bytes)")


def build_all_samples(samples_dir="samples"):
    """Builds all mock samples."""
    os.makedirs(samples_dir, exist_ok=True)

    apk_path = os.path.join(samples_dir, "sample.apk")
    build_sample_apk(apk_path)

    arm64_path = os.path.join(samples_dir, "sample_arm64.elf")
    with open(arm64_path, "wb") as f:
        f.write(make_arm64_elf_executable())
    os.chmod(arm64_path, 0o755)
    print(f"[+] Built AArch64 ELF sample: {arm64_path} ({os.path.getsize(arm64_path)} bytes)")

    x86_path = os.path.join(samples_dir, "sample_x86_64.elf")
    with open(x86_path, "wb") as f:
        f.write(make_x86_64_elf_executable())
    os.chmod(x86_path, 0o755)
    print(f"[+] Built x86_64 ELF sample: {x86_path} ({os.path.getsize(x86_path)} bytes)")


if __name__ == "__main__":
    build_all_samples()
