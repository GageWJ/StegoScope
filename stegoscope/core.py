import os
import re
import string
import subprocess
from PIL import Image


def run_all(file_path: str, outdir: str | None = None, flag_format: str = ""):
    """
    Core scanning engine.
    Runs each detection step in sequence: Strings → LSB → Binwalk (CLI).
    Stops early if a flag is found.
    """
    base_name = os.path.splitext(os.path.basename(file_path))[0]

    # Create auto-named output directory
    if not outdir:
        outdir = f"{base_name}_output"
        count = 2
        while os.path.exists(outdir):
            outdir = f"{base_name}_output{count}"
            count += 1
    os.makedirs(outdir, exist_ok=True)

    print(f"[CORE] Scanning file: {file_path}")
    print(f"[CORE] Flag format: {flag_format if flag_format else '(none)'}")

    # ── Step 1: Strings scan ──────────────────────────────────────────────
    if flag_format:
        found_flags = scan_for_flag(file_path, flag_format)
        if found_flags:
            print("\n[CORE] Flag(s) found in strings:")
            for f in found_flags:
                print(f"  - {f}")
            flags_out = os.path.join(outdir, "found_flags.txt")
            with open(flags_out, "w") as fh:
                fh.write("\n".join(found_flags))
            print(f"[CORE] Saved to {flags_out}")
            return outdir  # stop early
        else:
            print("[CORE] No flags found in strings. Moving on...")
    else:
        print("[CORE] Skipping strings step (no flag format).")

    # ── Step 2: LSB scan ──────────────────────────────────────────────────
    lsb_flags = scan_lsb(file_path, outdir, flag_format)
    if lsb_flags:
        print("\n[CORE] Flag(s) found in LSB:")
        for f in lsb_flags:
            print(f"  - {f}")
        flags_out = os.path.join(outdir, "found_flags.txt")
        with open(flags_out, "a") as fh:
            fh.write("\n[From LSB extraction]\n")
            fh.write("\n".join(lsb_flags))
        return outdir  # stop early

    # ── Step 3: Binwalk scan (CLI) ────────────────────────────────────────
    scan_binwalk_cli(file_path, outdir)

    # ── Step 4: Placeholders for future tools ─────────────────────────────
    for name in ["metadata_stub.txt", "steghide_stub.txt"]:
        with open(os.path.join(outdir, name), "w") as f:
            f.write(f"[CORE STUB] Placeholder for {name}\n")

    print("[CORE] No flags found in any step.")
    return outdir


# -------------------------------------------------------------------------
# Utility: Extract printable strings
# -------------------------------------------------------------------------
def extract_strings(data, min_length=4):
    """Fast printable-ASCII extraction using regex."""
    pattern = rb"[\x20-\x7E]{%d,}" % min_length
    return [s.decode("ascii", errors="ignore") for s in re.findall(pattern, data)]


# -------------------------------------------------------------------------
# Step 1: Strings scan
# -------------------------------------------------------------------------
def scan_for_flag(file_path, flag_format):
    """Searches extracted strings for flags matching the given format."""
    with open(file_path, "rb") as f:
        data = f.read()
    strings_found = extract_strings(data)

    prefix = flag_format.split("{")[0]
    pattern = re.escape(prefix) + r"\{[A-Za-z0-9_!@#$%^&*?.\-\s]+\}"
    regex = re.compile(pattern, re.IGNORECASE)

    return [s for s in strings_found if regex.search(s)]


# -------------------------------------------------------------------------
# Step 2: LSB scan
# -------------------------------------------------------------------------
def scan_lsb(file_path, outdir, flag_format=""):
    """Extracts Least Significant Bits and searches them for the flag format."""
    output_file = os.path.join(outdir, "lsb_extract.txt")
    found_flags = []

    try:
        img = Image.open(file_path)
        bits = "".join(str(c & 1) for p in list(img.getdata()) for c in p[:3])
        data = "".join(chr(int(bits[i:i + 8], 2)) for i in range(0, len(bits), 8) if len(bits[i:i + 8]) == 8)

        with open(output_file, "w") as f:
            f.write(data)
        print(f"[CORE] LSB data written to {output_file}")

        if flag_format:
            prefix = flag_format.split("{")[0]
            pattern = re.escape(prefix) + r"\{[A-Za-z0-9_!@#$%^&*?.\-\s]+\}"
            regex = re.compile(pattern, re.IGNORECASE)
            found_flags = regex.findall(data)
            if found_flags:
                with open(output_file, "a") as f:
                    f.write("\n\n[Possible flags found:]\n" + "\n".join(found_flags))
    except Exception as e:
        print(f"[CORE] Error in LSB scan: {e}")

    return found_flags


# -------------------------------------------------------------------------
# Step 3: Binwalk scan (CLI)
# -------------------------------------------------------------------------
def scan_binwalk_cli(file_path, outdir):
    """
    Runs Binwalk CLI and extracts embedded files using `binwalk -e`.
    Returns a list of discovered embedded file descriptions (cleaned).
    """
    results = []
    extract_dir = os.path.join(outdir, "binwalk_extracted")
    os.makedirs(extract_dir, exist_ok=True)

    try:
        print("[CORE] Running Binwalk CLI scan...")

        # Run binwalk and capture its output
        cmd = ["binwalk", "-e", file_path, "-C", extract_dir]
        result = subprocess.run(cmd, capture_output=True, text=True)

        # Save full raw output
        binwalk_log = os.path.join(outdir, "binwalk_raw_output.txt")
        with open(binwalk_log, "w") as f:
            f.write(result.stdout)

        # Extract meaningful rows only (ignore headers, summaries, etc.)
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line or line.startswith("-") or "DECIMAL" in line or "DESCRIPTION" in line:
                continue
            # Only include actual file discovery rows (not extraction logs)
            if re.match(r"^\d+", line):
                results.append(line)

        if results:
            results_file = os.path.join(outdir, "binwalk_results.txt")
            with open(results_file, "w") as f:
                f.write("[BINWALK RESULTS]\n")
                f.write("\n".join(results))
            print(f"[CORE] Binwalk found {len(results)} embedded file(s):")
            for r in results:
                print(f"  - {r}")
            print(f"[CORE] Extracted files saved to: {extract_dir}")
            print(f"[CORE] Binwalk results saved to {results_file}")
        else:
            print("[CORE] Binwalk completed, but no embedded file rows were detected.")

    except Exception as e:
        print(f"[CORE] Error during Binwalk CLI scan: {e}")

    return results

