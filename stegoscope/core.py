"""
StegoScope - Core Analysis Engine
---------------------------------
Main detection pipeline for steganographic analysis.

Detection modules:
  1. Strings-based flag search
  2. Least Significant Bit (LSB) data extraction
  3. Embedded file discovery using Binwalk CLI
"""

import os
import re
import subprocess
from PIL import Image


# =========================================================================
# Main Execution Function
# =========================================================================
def run_all(file_path: str, outdir: str | None = None, flag_format: str = ""):
    """
    Executes all StegoScope analysis steps in sequence:
      1. Strings-based flag detection
      2. LSB (Least Significant Bit) data extraction
      3. Binwalk embedded file extraction

    Args:
        file_path (str): Target file path.
        outdir (str | None): Optional output directory path.
        flag_format (str): Expected flag format (e.g., gctf{flag}).

    Returns:
        str: Path to output directory containing results.
    """
    base_name = os.path.splitext(os.path.basename(file_path))[0]

    # Create output directory (unique name if exists)
    if not outdir:
        outdir = f"{base_name}_output"
        counter = 2
        while os.path.exists(outdir):
            outdir = f"{base_name}_output{counter}"
            counter += 1
    os.makedirs(outdir, exist_ok=True)

    print(f"[CORE] Scanning file: {file_path}")
    print(f"[CORE] Flag format: {flag_format if flag_format else '(none)'}")

    # -------------------------------
    # Step 1: Strings-based scanning
    # -------------------------------
    if flag_format:
        found_flags = scan_for_flag(file_path, flag_format)
        if found_flags:
            print("\n[CORE] Flag(s) found in strings:")
            for f in found_flags:
                print(f"  - {f}")
            flags_path = os.path.join(outdir, "found_flags.txt")
            with open(flags_path, "w") as fh:
                fh.write("\n".join(found_flags))
            print(f"[CORE] Saved results to {flags_path}")
            return outdir
        else:
            print("[CORE] No flags found in strings. Moving on...")
    else:
        print("[CORE] Skipping strings scan (no flag format provided).")

    # -------------------------------
    # Step 2: LSB-based scanning
    # -------------------------------
    lsb_flags = scan_lsb(file_path, outdir, flag_format)
    if lsb_flags:
        print("\n[CORE] Flag(s) found in LSB data:")
        for f in lsb_flags:
            print(f"  - {f}")
        flags_path = os.path.join(outdir, "found_flags.txt")
        with open(flags_path, "a") as fh:
            fh.write("\n[From LSB Extraction]\n")
            fh.write("\n".join(lsb_flags))
        return outdir

    # -------------------------------
    # Step 3: Binwalk scan
    # -------------------------------
    scan_binwalk_cli(file_path, outdir)

    print("[CORE] No flags found in any step.")
    return outdir


# =========================================================================
# Utility: Extract Printable Strings
# =========================================================================
def extract_strings(data: bytes, min_length: int = 4):
    """Extracts printable ASCII strings from binary data."""
    pattern = rb"[\x20-\x7E]{%d,}" % min_length
    return [s.decode("ascii", errors="ignore") for s in re.findall(pattern, data)]


# =========================================================================
# Step 1: Strings Scan
# =========================================================================
def scan_for_flag(file_path: str, flag_format: str):
    """Searches extracted strings for matches to the provided flag format."""
    with open(file_path, "rb") as f:
        data = f.read()
    strings_found = extract_strings(data)

    prefix = flag_format.split("{")[0]
    pattern = re.escape(prefix) + r"\{[A-Za-z0-9_!@#$%^&*?.\-\s]+\}"
    regex = re.compile(pattern, re.IGNORECASE)

    return [s for s in strings_found if regex.search(s)]


# =========================================================================
# Step 2: LSB Extraction
# =========================================================================
def scan_lsb(file_path: str, outdir: str, flag_format: str = ""):
    """Extracts least significant bit data from an image and searches for flags."""
    output_file = os.path.join(outdir, "lsb_extract.txt")
    found_flags = []

    try:
        img = Image.open(file_path)
        bits = "".join(str(c & 1) for p in list(img.getdata()) for c in p[:3])
        data = "".join(
            chr(int(bits[i:i + 8], 2))
            for i in range(0, len(bits), 8)
            if len(bits[i:i + 8]) == 8
        )

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
                    f.write("\n\n[Possible Flags Found:]\n" + "\n".join(found_flags))

    except Exception as e:
        print(f"[CORE] Error in LSB scan: {e}")

    return found_flags


# =========================================================================
# Step 3: Binwalk CLI Integration
# =========================================================================
def scan_binwalk_cli(file_path: str, outdir: str):
    """
    Executes Binwalk CLI to detect and extract embedded files.

    Args:
        file_path (str): Target file for Binwalk scanning.
        outdir (str): Directory to store results.

    Returns:
        list[str]: Cleaned list of embedded file signatures.
    """
    results = []
    extract_dir = os.path.join(outdir, "binwalk_extracted")
    os.makedirs(extract_dir, exist_ok=True)

    try:
        print("[CORE] Running Binwalk CLI scan...")

        cmd = ["binwalk", "-e", file_path, "-C", extract_dir]
        result = subprocess.run(cmd, capture_output=True, text=True)

        # Save raw Binwalk output
        binwalk_log = os.path.join(outdir, "binwalk_raw_output.txt")
        with open(binwalk_log, "w") as f:
            f.write(result.stdout)

        # Parse meaningful output lines
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line or line.startswith("-") or "DECIMAL" in line or "DESCRIPTION" in line:
                continue
            if re.match(r"^\d+", line):
                results.append(line)

        if results:
            results_path = os.path.join(outdir, "binwalk_results.txt")
            with open(results_path, "w") as f:
                f.write("[BINWALK RESULTS]\n" + "\n".join(results))

            print(f"[CORE] Binwalk found {len(results)} embedded file(s):")
            for r in results:
                print(f"  - {r}")
            print(f"[CORE] Extracted files saved to: {extract_dir}")
            print(f"[CORE] Binwalk results saved to {results_path}")
        else:
            print("[CORE] Binwalk completed but found no embedded files.")

    except Exception as e:
        print(f"[CORE] Error during Binwalk CLI scan: {e}")

    return results

