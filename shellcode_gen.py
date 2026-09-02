#!/usr/bin/env python3
"""
Shellcode Gen — Shellcode Encoder & Format Converter for Red Team Payloads
Converts raw shellcode to C/Python/PowerShell/CSharp format with optional XOR/NOT encoding.
Does NOT generate shellcode — takes existing shellcode as input and reformats/encodes it.
Author: Omar Khalid (amooryx) | github.com/amooryx/shellcode-gen
AUTHORIZED USE ONLY — for authorized red team engagements and security research.
"""

import argparse
import base64
import hashlib
import json
import os
import sys

def xor_encode(data: bytes, key: int) -> bytes:
    return bytes(b ^ key for b in data)

def not_encode(data: bytes) -> bytes:
    return bytes(~b & 0xFF for b in data)

def derive_key(passphrase: str) -> bytes:
    return hashlib.sha256(passphrase.encode()).digest()

def xor_encode_key(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

def format_c(data: bytes, var_name: str = "shellcode") -> str:
    hex_bytes = ", ".join(f"0x{b:02x}" for b in data)
    return (f"unsigned char {var_name}[] = {{\n"
            + "\n".join("    " + ", ".join(f"0x{b:02x}" for b in data[i:i+16])
                        for i in range(0, len(data), 16))
            + "\n};\n"
            + f"size_t {var_name}_len = {len(data)};")

def format_python(data: bytes, var_name: str = "shellcode") -> str:
    b64 = base64.b64encode(data).decode()
    return (f"import base64\n"
            f"{var_name} = base64.b64decode(\"{b64}\")\n"
            f"# Length: {len(data)} bytes")

def format_powershell(data: bytes, var_name: str = "shellcode") -> str:
    hex_bytes = ",".join(f"0x{b:02x}" for b in data)
    return (f"[Byte[]] ${var_name} = {hex_bytes}\n"
            f"# Length: {len(data)} bytes")

def format_csharp(data: bytes, var_name: str = "shellcode") -> str:
    hex_bytes = ", ".join(f"0x{b:02x}" for b in data)
    return (f"byte[] {var_name} = new byte[] {{\n"
            + "\n".join("    " + ", ".join(f"0x{b:02x}" for b in data[i:i+16])
                        for i in range(0, len(data), 16))
            + "\n};")

def format_base64(data: bytes) -> str:
    return base64.b64encode(data).decode()

def format_hex(data: bytes) -> str:
    return data.hex()

FORMATS = {
    "c":          format_c,
    "python":     format_python,
    "powershell": format_powershell,
    "csharp":     format_csharp,
    "base64":     format_base64,
    "hex":        format_hex,
}

def main():
    parser = argparse.ArgumentParser(
        description="Shellcode Gen — Shellcode Encoder & Format Converter (Authorized use only)",
    )
    parser.add_argument("input",        help="Input shellcode file (.bin) or '-' for stdin")
    parser.add_argument("--format", "-f", choices=list(FORMATS.keys()), default="c",
                        help="Output format")
    parser.add_argument("--encode",     choices=["none", "xor", "xor-key", "not"],
                        default="none",  help="Encoding method")
    parser.add_argument("--xor-byte",   type=lambda x: int(x, 0), default=0xAA,
                        help="XOR byte for single-byte XOR (hex ok: 0xAA)")
    parser.add_argument("--key",        default="authorized_test",
                        help="Passphrase for key-derived XOR")
    parser.add_argument("--var",        default="shellcode", help="Variable name in output")
    parser.add_argument("--out",        help="Output file (stdout if omitted)")
    parser.add_argument("--stats",      action="store_true", help="Print shellcode stats")
    args = parser.parse_args()

    print("[!] AUTHORIZED USE ONLY — for authorized red team engagements")

    # Read shellcode
    if args.input == "-":
        shellcode = sys.stdin.buffer.read()
    else:
        with open(args.input, "rb") as f:
            shellcode = f.read()

    original_len = len(shellcode)
    print(f"[*] Input: {original_len} bytes | MD5: {hashlib.md5(shellcode).hexdigest()}")

    # Encode
    if args.encode == "xor":
        shellcode = xor_encode(shellcode, args.xor_byte)
        print(f"[*] XOR encoded with byte: 0x{args.xor_byte:02x}")
        print(f"[*] Decoder stub needed: xor each byte with 0x{args.xor_byte:02x}")
    elif args.encode == "xor-key":
        key = derive_key(args.key)
        shellcode = xor_encode_key(shellcode, key)
        print(f"[*] XOR-key encoded | Key SHA-256: {key.hex()[:32]}...")
    elif args.encode == "not":
        shellcode = not_encode(shellcode)
        print("[*] NOT encoded (bitwise NOT of each byte)")

    # Format
    formatter = FORMATS[args.format]
    output = formatter(shellcode, args.var) if args.format not in ("base64", "hex") \
             else formatter(shellcode)

    if args.stats:
        null_bytes = shellcode.count(0x00)
        print(f"[*] Stats: {len(shellcode)} bytes | NULL bytes: {null_bytes} ({null_bytes/len(shellcode)*100:.1f}%)")

    if args.out:
        with open(args.out, "w") as f:
            f.write(output)
        print(f"[*] Output ({args.format}) → {args.out}")
    else:
        print(f"\n{'='*60}")
        print(output)

if __name__ == "__main__":
    main()
