# StegoScope

**StegoScope** is an automated steganography scanner designed mainly for Capture The Flag (CTF) participants. 
It performs a layered analysis of image files to detect hidden data, readable text, and embedded files.

---

## Overview

StegoScope performs three core analyses on image files:

1. **Strings-based Analysis** – Extracts readable text, filenames, URLs, and potential flags.  
2. **LSB Extraction** – Recovers hidden data encoded in image pixels’ least significant bits.  
3. **Binwalk Scan** – Detects and extracts embedded files (e.g., images, archives) using Binwalk.

All results are saved to a structured output directory for easy review.

---

## Installation Guide

1. Install Python 3.8 or newer

2. Clone the Repository: 
git clone https://github.com/gagejohnson/stegoscope.git

cd stegoscope

3. Install Dependencies: 
StegoScope requires a few Python libraries and the Binwalk tool.

Install Python dependencies: pip install .

Install Binwalk:
macOS (Homebrew): brew install binwalk
Debian/Ubuntu:sudo apt install binwalk

4. Usage: 
Once installed, run StegoScope through the command line.

stegoscope analyze image.png

This performs all three analysis steps and saves results in: image_output/

License: 
This project is licensed under the MIT License.
You may freely use, modify, and distribute this software under its terms.

Author: 
Gage Johnson

