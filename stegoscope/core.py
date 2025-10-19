# stegoscope/core.py

import os
import re
import string


def run_all(file_path: str, outdir: str, flag_format: str = ""):
    """
    Core scanning engine (currently partially implemented).
    Creates output folder, performs basic scans, and prints progress.
    """
    os.makedirs(outdir, exist_ok=True)

    print(f"[CORE] Scanning file: {file_path}")
    if flag_format:
        print(f"[CORE] Using flag format: {flag_format}")
    else:
        print("[CORE] No flag format provided")

    # --- Step 1: Strings-based scan ---
    if flag_format:
        found_flags = scan_for_flag(file_path, flag_format)
        if found_flags:
            print("\n[CORE] Possible flags found:")
            for f in found_flags:
                print(f"  - {f}")
            # Save results
            flags_out = os.path.join(outdir, "found_flags.txt")
            with open(flags_out, "w") as fh:
                fh.write("\n".join(found_flags))
            print(f"[CORE] Saved found flags to {flags_out}")
        else:
            print("[CORE] No flags matching that format were found.")
    else:
        print("[CORE] Skipping string-based flag scan (no format provided).")

    # --- Step 2: Placeholder for other modules ---
    placeholder_files = [
        "lsb_stub.bin",
        "metadata_stub.txt",
        "steghide_stub.txt",
        "binwalk_stub.txt"
    ]
    for f in placeholder_files:
        path = os.path.join(outdir, f)
        with open(path, "w") as fh:
            fh.write(f"[CORE STUB] Placeholder for {f}\n")

    print(f"[CORE] Placeholder outputs created in {outdir}")


def extract_strings(data, min_length=4):
    """Extracts printable strings from binary data."""
    result = []
    current = ""
    for byte in data:
        char = chr(byte)
        if char in string.printable and not char.isspace():
            current += char
        else:
            if len(current) >= min_length:
                result.append(current)
            current = ""
    if len(current) >= min_length:
        result.append(current)
    return result


def scan_for_flag(file_path, flag_format):
    """Scans a file for potential flags matching the given format."""
    with open(file_path, "rb") as f:
        data = f.read()

    found_flags = []
    strings_found = extract_strings(data)

    # Build a flexible regex pattern from the flag format
    # Example: gctf{flag} -> r"gctf\{[A-Za-z0-9_!@#$%^&*?.-]+\}"
    pattern = re.escape(flag_format.split("{")[0]) + r"\{[A-Za-z0-9_!@#$%^&*?.-]+\}"
    regex = re.compile(pattern)

    for s in strings_found:
        if regex.search(s):
            found_flags.append(s)

    return found_flags

