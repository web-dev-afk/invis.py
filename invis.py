#!/usr/bin/env python3
"""
invis.py — Invisible character steganography decoder

Pemakaian:
  python3 invis.py <file>
  python3 invis.py flag.txt

Mendukung:
  - 2-bit encoding (4 jenis invisible char → 2 bit tiap char)
  - 1-bit encoding (2 jenis invisible char → 1 bit tiap char)
  - Semua permutasi mapping otomatis dicoba

Output encoding pilihan:
  0 → semua sekaligus
  1 → ASCII
  2 → UTF-8
  3 → UTF-16 BE
  4 → UTF-16 LE
  5 → UTF-32 BE
  6 → UTF-32 LE
  7 → Shift_JIS
  8 → EUC-JP
"""

import sys
import itertools
from collections import Counter

# ─────────────────────── definisi invisible chars ───────────────────────

INVISIBLE_CHARS = {
    0x0009: "TAB",
    0x00AD: "SOFT HYPHEN",
    0x034F: "COMBINING GRAPHEME JOINER",
    0x061C: "ARABIC LETTER MARK",
    0x115F: "HANGUL CHOSEONG FILLER",
    0x1160: "HANGUL JUNGSEONG FILLER",
    0x17B4: "KHMER VOWEL INHERENT AQ",
    0x17B5: "KHMER VOWEL INHERENT AA",
    0x180B: "MONGOLIAN FREE VARIATION SELECTOR ONE",
    0x180C: "MONGOLIAN FREE VARIATION SELECTOR TWO",
    0x180D: "MONGOLIAN FREE VARIATION SELECTOR THREE",
    0x180E: "MONGOLIAN VOWEL SEPARATOR",
    0x200B: "ZERO WIDTH SPACE",
    0x200C: "ZERO WIDTH NON-JOINER",
    0x200D: "ZERO WIDTH JOINER",
    0x200E: "LEFT-TO-RIGHT MARK",
    0x200F: "RIGHT-TO-LEFT MARK",
    0x2028: "LINE SEPARATOR",
    0x2029: "PARAGRAPH SEPARATOR",
    0x202A: "LEFT-TO-RIGHT EMBEDDING",
    0x202B: "RIGHT-TO-LEFT EMBEDDING",
    0x202C: "POP DIRECTIONAL FORMATTING",
    0x202D: "LEFT-TO-RIGHT OVERRIDE",
    0x202E: "RIGHT-TO-LEFT OVERRIDE",
    0x2060: "WORD JOINER",
    0x2061: "FUNCTION APPLICATION",
    0x2062: "INVISIBLE TIMES",
    0x2063: "INVISIBLE SEPARATOR",
    0x2064: "INVISIBLE PLUS",
    0xFEFF: "BOM / ZERO WIDTH NO-BREAK SPACE",
    0xFFF9: "INTERLINEAR ANNOTATION ANCHOR",
    0xFFFA: "INTERLINEAR ANNOTATION SEPARATOR",
    0xFFFB: "INTERLINEAR ANNOTATION TERMINATOR",
}

ENCODING_MENU = {
    "1": ("ASCII",    "ascii"),
    "2": ("UTF-8",    "utf-8"),
    "3": ("UTF-16 BE","utf-16-be"),
    "4": ("UTF-16 LE","utf-16-le"),
    "5": ("UTF-32 BE","utf-32-be"),
    "6": ("UTF-32 LE","utf-32-le"),
    "7": ("Shift_JIS","shift_jis"),
    "8": ("EUC-JP",   "euc_jp"),
}

# ─────────────────────── helpers ───────────────────────

def show_banner():
    print("=" * 55)
    print("  invis.py — Mencari invisible karakter dalam hex")
    print("=" * 55)

def is_invisible(ch: str) -> bool:
    return ord(ch) in INVISIBLE_CHARS

def extract_invisible(text: str) -> list:
    return [ch for ch in text if is_invisible(ch)]

def try_decode(raw: bytes, encoding: str) -> str:
    try:
        result = raw.decode(encoding, errors='replace')
        printable_ratio = sum(c.isprintable() for c in result) / max(len(result), 1)
        return result if printable_ratio > 0.5 else None
    except (LookupError, UnicodeDecodeError):
        return None

def bits_to_bytes(bits: str) -> bytes:
    n = (len(bits) // 8) * 8
    if n == 0:
        return b""
    return int(bits[:n], 2).to_bytes(n // 8, 'big')

def score_result(text: str) -> int:
    """Skor sederhana: makin banyak printable ASCII, makin tinggi."""
    if not text:
        return 0
    return sum(1 for c in text if 0x20 <= ord(c) <= 0x7E or c in '\n\t')

def score_raw_per_enc(raw: bytes, enc_code: str) -> int:
    """
    Skor encoding-aware: tiap encoding punya ekspektasi pola byte yang berbeda.
    Ini mencegah UTF-16 BE (penuh null byte) kalah dari ASCII saat scoring.
    """
    if not raw:
        return 0
    try:
        text = raw.decode(enc_code, errors='strict')
        # kalau bisa decode tanpa error, hitung printable
        printable = sum(1 for c in text if c.isprintable() or c in '\n\t ')
        return printable * 10
    except (UnicodeDecodeError, LookupError):
        pass
    # decode dengan replace — lihat berapa yang bisa diselamatkan
    try:
        text = raw.decode(enc_code, errors='replace')
        good = sum(1 for c in text if c.isprintable() and c != '\ufffd')
        return good * 2
    except LookupError:
        return 0

def decode_and_show(raw: bytes, chosen_encs: list, label: str = ""):
    if label:
        print(f"\n{'─'*45}")
        print(f"  Hasil: {label}")
        print(f"{'─'*45}")
    for enc_name, enc_code in chosen_encs:
        result = try_decode(raw, enc_code)
        if result:
            cleaned = ''.join(c if c.isprintable() or c == '\n' else f'[U+{ord(c):04X}]' for c in result)
            print(f"  [{enc_name}] {cleaned}")
        else:
            print(f"  [{enc_name}] (gagal decode / tidak printable)")

# ─────────────────────── strategi 1-bit ───────────────────────

def try_1bit(inv_chars: list, chosen_encs: list):
    """
    1-bit: 2 jenis karakter berbeda → 0 dan 1.
    Coba semua kombinasi pasangan yang mungkin.
    """
    unique = sorted(set(inv_chars), key=lambda c: ord(c))
    if len(unique) < 2:
        return None

    best_score = -1
    best_result = None

    for a, b in itertools.combinations(unique, 2):
        for bit_a, bit_b in [("0","1"), ("1","0")]:
            bits = ""
            for ch in inv_chars:
                if ch == a:
                    bits += bit_a
                elif ch == b:
                    bits += bit_b
                # karakter lain diabaikan
            raw = bits_to_bytes(bits)
            if not raw:
                continue
            total_score = sum(score_raw_per_enc(raw, enc_code) for _, enc_code in chosen_encs)
            if total_score > best_score:
                best_score = total_score
                best_result = (a, b, bit_a, bit_b, raw, bits)

    return best_result if best_score > 0 else None

# ─────────────────────── strategi 2-bit ───────────────────────

def try_2bit(inv_chars: list, chosen_encs: list):
    """
    2-bit: 4 jenis karakter → 00, 01, 10, 11.
    Coba semua permutasi mapping yang mungkin (4! = 24 kombinasi).
    """
    unique = sorted(set(inv_chars), key=lambda c: ord(c))
    if len(unique) < 3:
        return None

    bit_values = ["00","01","10","11"]

    best_score = -1
    best_result = None

    # kalau ada > 4 jenis, ambil 4 yang paling sering dulu
    if len(unique) > 4:
        freq = Counter(inv_chars)
        unique = [ch for ch, _ in freq.most_common(4)]

    for perm in itertools.permutations(unique[:4]):
        mapping = {ch: bv for ch, bv in zip(perm, bit_values)}
        bits = "".join(mapping.get(ch, "") for ch in inv_chars)
        raw = bits_to_bytes(bits)
        if not raw:
            continue
        # skor gabungan dari SEMUA encoding yang dipilih
        total_score = sum(score_raw_per_enc(raw, enc_code) for _, enc_code in chosen_encs)
        if total_score > best_score:
            best_score = total_score
            best_result = (mapping, raw, bits)

    return best_result if best_score > 0 else None

# ─────────────────────── show menu encoding ───────────────────────

def ask_encoding() -> list:
    print("\nPilih bahasa konversi output:")
    print("  0 → Semua bahasa sekaligus")
    for key, (name, _) in ENCODING_MENU.items():
        print(f"  {key} → {name}")
    print()
    choice = input("Masukkan pilihan (0-8): ").strip()
    if choice == "0":
        return list(ENCODING_MENU.values())
    elif choice in ENCODING_MENU:
        return [ENCODING_MENU[choice]]
    else:
        print("[!] Pilihan tidak valid, menggunakan semua bahasa.")
        return list(ENCODING_MENU.values())

# ─────────────────────── main ───────────────────────

def main():
    show_banner()

    if len(sys.argv) < 2:
        print("Pemakaian: python3 invis.py <file>")
        sys.exit(0)

    path = sys.argv[1]
    try:
        raw_bytes = open(path, 'rb').read()
    except FileNotFoundError:
        sys.exit(f"[!] File tidak ditemukan: {path}")

    try:
        text = raw_bytes.decode('utf-8', errors='replace')
    except Exception as e:
        sys.exit(f"[!] Gagal baca file: {e}")

    # ── inventaris ──
    inv_chars = extract_invisible(text)
    total_chars = len(text)
    total_inv = len(inv_chars)

    print(f"\n[info] File       : {path}")
    print(f"[info] Total char : {total_chars}")
    print(f"[info] Invisible  : {total_inv}")

    if total_inv == 0:
        print("\n[!] Tidak ada karakter invisible ditemukan.")
        sys.exit(0)

    # ── distribusi ──
    freq = Counter(ord(ch) for ch in inv_chars)
    unique_inv = len(freq)
    print(f"[info] Jenis unik : {unique_inv}")
    print()
    print("Distribusi invisible chars:")
    for cp, count in sorted(freq.items(), key=lambda x: -x[1]):
        name = INVISIBLE_CHARS.get(cp, f"U+{cp:04X}")
        bar = "█" * min(count // 3 + 1, 30)
        print(f"  U+{cp:04X}  {name:35s}  {count:4d}x  {bar}")

    # ── tanya encoding ──
    chosen_encs = ask_encoding()

    print(f"\n[~] Mencoba {len(chosen_encs)} encoding dengan 2 strategi (1-bit dan 2-bit)...")

    hasil_ditemukan = False

    # ── strategi 1-bit ──
    if unique_inv >= 2:
        res = try_1bit(inv_chars, chosen_encs)
        if res:
            a, b, bit_a, bit_b, raw, bits = res
            ua, ub = f"U+{ord(a):04X}", f"U+{ord(b):04X}"
            label = f"1-bit encoding  ({ua}={bit_a}, {ub}={bit_b})"
            print(f"\n[√] STRATEGI 1-BIT BERHASIL")
            print(f"    Mapping: {ua} → {bit_a},  {ub} → {bit_b}")
            print(f"    Total bits  : {len(bits)}")
            print(f"    Total bytes : {len(raw)}")
            print(f"    Hex: {raw.hex()}")
            decode_and_show(raw, chosen_encs, label)
            hasil_ditemukan = True

    # ── strategi 2-bit ──
    if unique_inv >= 3:
        res = try_2bit(inv_chars, chosen_encs)
        if res:
            mapping, raw, bits = res
            map_str = "  ".join(
                f"U+{ord(ch):04X}={bv}" for ch, bv in sorted(mapping.items(), key=lambda x: x[1])
            )
            print(f"\n[√] STRATEGI 2-BIT BERHASIL")
            print(f"    Mapping: {map_str}")
            print(f"    Total bits  : {len(bits)}")
            print(f"    Total bytes : {len(raw)}")
            print(f"    Hex: {raw.hex()}")
            decode_and_show(raw, chosen_encs, "2-bit encoding")
            hasil_ditemukan = True

    if not hasil_ditemukan:
        print("\n[!] Tidak ada hasil yang bisa didecode dengan encoding yang dipilih.")
        print("    Coba pilihan encoding yang berbeda, atau file ini mungkin pakai")
        print("    skema encoding kustom yang tidak terdeteksi otomatis.")

    print()

if __name__ == "__main__":
    main()
