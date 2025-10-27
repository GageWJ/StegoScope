# stegoscope/cli.py

import os
import click
from rich.console import Console
from rich.prompt import Prompt
from rich.text import Text
from .core import run_all

console = Console()
VERSION = "v1.0.0"


@click.group()
def main():
    """StegoScope - Automated Steganography Scanner"""
    pass


@main.command()
@click.argument("file", type=click.Path(exists=True))
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
    help="Skip interactive prompt; use --flag-format instead.",
)
def analyze(file, flag_format, no_prompt):
    """Analyze FILE for steganography. Prompts for flag format unless --no-prompt is used."""

    # Display banner 
    banner_path = os.path.join(os.path.dirname(__file__), "assets", "banner.txt")
    if os.path.exists(banner_path):
        with open(banner_path, "r") as f:
            banner_text = f.read()
        console.print(f"[white]{banner_text}[/white]")
    else:
        console.print("[bold white]StegoScope[/bold white]")

    version_text = Text(f"StegoScope {VERSION} — Automated Steganography Scanner", style="dim cyan")
    console.print(version_text)
    console.print()  

    # Prompt for flag format
    if not flag_format and not no_prompt:
        console.print("[bold cyan]Enter flag format (e.g. gctf{flag}) or press Enter to skip:[/]")
        flag_format = Prompt.ask("Flag format", default="").strip()

    console.print(f"\n[yellow]Scanning file:[/] {file}\n")

    # Run analysis 
    output_dir = run_all(file, None, flag_format)

    # Final output summary
    console.print("\n[bold green]Scan completed successfully![/bold green]")
    console.print(f"Results saved in: [italic cyan]{output_dir}[/italic cyan]\n")

    # Display found flags 
    flags_path = os.path.join(output_dir, "found_flags.txt")
    if os.path.exists(flags_path):
        with open(flags_path, "r") as fh:
            found_flags = [line.strip() for line in fh if line.strip()]
        if found_flags:
            console.print("\n[bold yellow]Flags Found:[/bold yellow]")
            for f in found_flags:
                console.print(f"  • [green]{f}[/green]")
        else:
            console.print("[bold red]No flags found in file.[/bold red]")
    else:
        console.print("[bold red]No flags found in file.[/bold red]")

    # Shows generated output files
    output_files = [
        "lsb_extract.txt",
        "binwalk_results.txt",
        "binwalk_raw_output.txt",
        f"Extracted files directory: {os.path.join(output_dir, 'binwalk_extracted')}"
    ]
    console.print("\n[bold yellow]Generated output files:[/bold yellow]")
    for f in output_files:
        console.print(f"  • [cyan]{f}[/cyan]")


if __name__ == "__main__":
    main()

