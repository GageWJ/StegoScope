"""
StegoScope - Core Analysis Engine
---------------------------------
Primary detection pipeline for steganographic and hidden data analysis.

Detection modules:
  1. Strings-based flag and text discovery
  2. Least Significant Bit (LSB) data extraction
  3. Embedded file discovery via Binwalk CLI
"""

import os
import re
import subprocess
from PIL import Image
from rich.console import Console
from rich.text import Text

console = Console()


# =========================================================================
# Main Execution Function
# =========================================================================
def run_all(file_path: str, outdir: str | None = None, flag_format: str = ""):
    """Executes all StegoScope analysis steps in sequence."""
    base_name = os.path.splitext(os.path.basename(file_path))[0]

    # Create output directory (unique name if exists)
    if not outdir:
        outdir = f"{base_name}_output"
        counter = 2
        while os.path.exists(outdir):
            outdir = f"{base_name}_output{counter}"
            counter += 1
    os.makedirs(outdir, exist_ok=True)

    console.print(f"[cyan][CORE][/cyan] Scanning file: {file_path}")
    console.print(f"[cyan][CORE][/cyan] Flag format: {flag_format if flag_format else '(none)'}")

    # -------------------------------
    # Step 1: Strings-based scanning
    # -------------------------------
    found_flags = []
    if flag_format:
        found_flags = scan_for_flag(file_path, flag_format)
        if found_flags:
            console.print("\n[cyan][CORE][/cyan] Flag(s) found in strings:")
            for f in found_flags:
                console.print(f"  - {f}")
            flags_path = os.path.join(outdir, "found_flags.txt")
            with open(flags_path, "w") as fh:
                fh.write("\n".join(found_flags))
            console.print(f"[cyan][CORE][/cyan] Saved results to {flags_path}")
            return outdir
        else:
            console.print("[cyan][CORE][/cyan] No flags found in strings. Checking for other readable data...")
    else:
        console.print("[cyan][CORE][/cyan] Skipping flag search (no flag format provided).")

    # Step 1B: Detect readable text, URLs, and file-like strings
    extra_text = scan_for_text_and_files(file_path)
    if extra_text:
        console.print(f"\n[cyan][CORE][/cyan] Found {len(extra_text)} readable or file-related strings:")
        for line in extra_text[:10]:  # Limit output
            console.print(Text(f"  - {line}", style="dim"))
        extra_path = os.path.join(outdir, "interesting_strings.txt")
        with open(extra_path, "w") as f:
            f.write("\n".join(extra_text))
        console.print(f"[cyan][CORE][/cyan] Saved readable string results to {extra_path}")

    # -------------------------------
    # Step 2: LSB-based scanning
    # -------------------------------
    lsb_flags = scan_lsb(file_path, outdir, flag_format)
    if lsb_flags:
        console.print("\n[cyan][CORE][/cyan] Flag(s) found in LSB data:")
        for f in lsb_flags:
            console.print(f"  - {f}")
        flags_path = os.path.join(outdir, "found_flags.txt")
        with open(flags_path, "a") as fh:
            fh.write("\n[From LSB Extraction]\n")
            fh.write("\n".join(lsb_flags))
        return outdir

    # -------------------------------
    # Step 3: Binwalk scan
    # -------------------------------
    scan_binwalk_cli(file_path, outdir)

    console.print("[cyan][CORE][/cyan] Analysis complete — no flags found in any step.")
    return outdir


# =========================================================================
# Utility: Extract Printable Strings
# =========================================================================
def extract_strings(data: bytes, min_length: int = 4):
    """Extracts printable ASCII strings from binary data."""
    pattern = rb"[\x20-\x7E]{%d,}" % min_length
    return [s.decode("ascii", errors="ignore") for s in re.findall(pattern, data)]


# =========================================================================
# Step 1A: Flag Search
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
# Step 1B: Detect Readable Text, Paths, and Filenames
# =========================================================================
def scan_for_text_and_files(file_path: str):
    """Detects readable text, URLs, file paths, and filenames from extracted strings."""
    with open(file_path, "rb") as f:
        data = f.read()

    strings_found = extract_strings(data, min_length=4)
    interesting = []

    exts = [
        ".txt", ".html", ".htm", ".php", ".py", ".sh", ".zip", ".tar", ".gz",
        ".png", ".jpg", ".jpeg", ".bmp", ".doc", ".pdf", ".csv", ".json",
        ".xml", ".key", ".pem", ".conf", ".exe"
    ]

    file_pattern = re.compile(
        r"(?:[A-Za-z0-9_\-/.\\:]+(?:"
        + "|".join([re.escape(ext) for ext in exts])
        + r"))",
        re.IGNORECASE,
    )
    url_pattern = re.compile(r"https?://[A-Za-z0-9./_\-]+", re.IGNORECASE)
    path_pattern = re.compile(r"(?:/[^ ]+/[^ ]+|[A-Za-z]:\\[^ ]+)", re.IGNORECASE)
    readable_pattern = re.compile(r"[A-Z][a-z’']+(?: [A-Za-z0-9’'\",!?.:-]+){3,}")

    ignore_domains = ["adobe.com", "w3.org", "purl.org", "schemas.microsoft.com", "ns.adobe.com", "xmlns"]

    for s in strings_found:
        s = s.strip()
        if len(s) < 5:
            continue
        if not re.search(r"[A-Za-z0-9]", s):
            continue
        if len(re.sub(r"[A-Za-z0-9]", "", s)) > len(s) * 0.6:
            continue
        if any(domain in s.lower() for domain in ignore_domains):
            continue

        if (
            file_pattern.search(s)
            or url_pattern.search(s)
            or path_pattern.search(s)
            or readable_pattern.search(s)
        ):
            interesting.append(s)

    return list(set(interesting))


# =========================================================================
# Step 2: LSB Extraction (Enhanced)
# =========================================================================
def scan_lsb(file_path: str, outdir: str, flag_format: str = ""):
    """Extracts least significant bit (LSB) data from an image and searches for flags."""
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
        console.print(f"[cyan][CORE][/cyan] LSB data written to {output_file}")

        if flag_format:
            prefix = flag_format.split("{")[0]
            pattern = re.escape(prefix) + r"\{[A-Za-z0-9_!@#$%^&*?.\-\s]+\}"
            regex = re.compile(pattern, re.IGNORECASE)
            found_flags = regex.findall(data)
            if found_flags:
                with open(output_file, "a") as f:
                    f.write("\n\n[Possible Flags Found:]\n" + "\n".join(found_flags))

        # Detect readable text / paths / files in LSB
        temp_file = os.path.join(outdir, "_lsb_temp.txt")
        with open(temp_file, "w") as f:
            f.write(data)

        interesting = scan_for_text_and_files(temp_file)
        os.remove(temp_file)

        if interesting:
            lsb_interesting_path = os.path.join(outdir, "lsb_interesting.txt")
            with open(lsb_interesting_path, "w") as f:
                f.write("\n".join(interesting))
            console.print(f"[cyan][CORE][/cyan] Found {len(interesting)} readable or file-related strings in LSB:")
            for s in interesting[:10]:
                console.print(Text(f"  - {s}", style="dim"))
            console.print(f"[cyan][CORE][/cyan] Saved LSB readable strings to {lsb_interesting_path}")
        else:
            console.print("[cyan][CORE][/cyan] No readable data detected in LSB.")

    except Exception as e:
        console.print(f"[cyan][CORE][/cyan] Error in LSB scan: {e}")

    return found_flags


# =========================================================================
# Step 3: Binwalk CLI Integration
# =========================================================================
def scan_binwalk_cli(file_path: str, outdir: str):
    """Executes Binwalk CLI to detect and extract embedded files."""
    results = []
    extract_dir = os.path.join(outdir, "binwalk_extracted")
    os.makedirs(extract_dir, exist_ok=True)

    try:
        console.print("[cyan][CORE][/cyan] Running Binwalk CLI scan...")

        cmd = ["binwalk", "-e", file_path, "-C", extract_dir]
        result = subprocess.run(cmd, capture_output=True, text=True)

        binwalk_log = os.path.join(outdir, "binwalk_raw_output.txt")
        with open(binwalk_log, "w") as f:
            f.write(result.stdout)

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
            console.print(f"[cyan][CORE][/cyan] Binwalk found {len(results)} embedded file(s):")
            for r in results:
                console.print(Text(f"  - {r}", style="dim"))
            console.print(f"[cyan][CORE][/cyan] Extracted files saved to: {extract_dir}")
            console.print(f"[cyan][CORE][/cyan] Binwalk results saved to {results_path}")
        else:
            console.print("[cyan][CORE][/cyan] Binwalk completed but found no embedded files.")

    except Exception as e:
        console.print(f"[cyan][CORE][/cyan] Error during Binwalk CLI scan: {e}")

    return results

