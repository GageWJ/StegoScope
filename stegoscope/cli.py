# stegoscope/cli.py

import os
import click
from rich.console import Console
from rich.prompt import Prompt
from .core import run_all  # stub function for now

console = Console()


@click.group()
def main():
    """StegoScope - Automated steganography scanner"""
    pass


@main.command()
@click.argument("file", type=click.Path(exists=True))
@click.option(
    "--outdir",
    "-o",
    default="output",
    help="Directory to save scan outputs (will be created if not exists)",
)
@click.option(
    "--flag-format",
    "-f",
    default="",
    help="Flag template (e.g., gctf{flag}) or raw regex with prefix 're:'. Leave empty to skip flag search.",
)
@click.option(
    "--no-prompt",
    is_flag=True,
    default=False,
    help="Skip interactive prompt; use --flag-format instead",
)
def analyze(file, outdir, flag_format, no_prompt):
    """
    Analyze FILE for steganography. Prompts for flag format unless --no-prompt is used.
    """
    # Display banner
    banner_path = os.path.join(os.path.dirname(__file__), "assets", "banner.txt")
    if os.path.exists(banner_path):
        with open(banner_path, "r") as f:
            console.print(f.read())

    # Prompt for flag format if not supplied
    if not flag_format and not no_prompt:
        console.print("[bold cyan]Enter flag format (e.g. gctf{flag}) or press Enter to skip:[/]")
        flag_format = Prompt.ask("Flag format", default="").strip()

    # Create output directory if needed
    os.makedirs(outdir, exist_ok=True)
    console.print(f"[green]Outputs will be saved to:[/] {outdir}")

    # Call core scanner (stub for now)
    console.print(f"[yellow]Scanning file:[/] {file} ...")
    run_all(file, outdir, flag_format=flag_format)
    console.print("[bold green]Scan completed![/]")


if __name__ == "__main__":
    main()

