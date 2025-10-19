# stegoscope/cli.py

import os
import click
from rich.console import Console
from rich.prompt import Prompt
from rich.panel import Panel
from rich.progress import Progress
from .core import run_all

console = Console()


@click.group()
def main():
    """StegoScope - Automated steganography scanner"""
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
    help="Skip interactive prompt; use --flag-format instead",
)
def analyze(file, flag_format, no_prompt):
    """
    Analyze FILE for steganography. Prompts for flag format unless --no-prompt is used.
    """
    # --- Display banner ---
    banner_path = os.path.join(os.path.dirname(__file__), "assets", "banner.txt")
    if os.path.exists(banner_path):
        with open(banner_path, "r") as f:
            console.print(Panel.fit(f.read(), border_style="cyan"))

    # --- Prompt for flag format if not supplied ---
    if not flag_format and not no_prompt:
        console.print("[bold cyan]Enter flag format (e.g. gctf{flag}) or press Enter to skip:[/]")
        flag_format = Prompt.ask("Flag format", default="").strip()

    # --- Run scan with progress indicator ---
    console.print(f"[yellow]Scanning file:[/] {file}\n")

    with Progress() as progress:
        task = progress.add_task("[cyan]Running scans...", total=4)
        progress.update(task, description="[cyan]Step 1: Searching for flag format...", advance=1)
        output_dir = run_all(file, None, flag_format)
        progress.update(task, description="[cyan]Step 2: LSB scan placeholder...", advance=1)
        progress.update(task, description="[cyan]Step 3: Metadata scan placeholder...", advance=1)
        progress.update(task, description="[cyan]Step 4: Binwalk scan placeholder...", advance=1)

    console.print("\n[bold green]✅ Scan completed successfully![/bold green]")
    console.print(f"[green]Results saved in:[/] [italic]{output_dir}[/italic]\n")

    # --- Print found flags if any ---
    flags_path = os.path.join(output_dir, "found_flags.txt")
    if os.path.exists(flags_path):
        with open(flags_path, "r") as fh:
            found_flags = [line.strip() for line in fh if line.strip()]
        if found_flags:
            console.print(Panel.fit(
                "\n".join(found_flags),
                title="[bold yellow]Flags Found[/bold yellow]",
                border_style="green"
            ))
        else:
            console.print("[bold red]No flags found in file.[/bold red]")
    else:
        console.print("[bold red]No flags found in file.[/bold red]")


if __name__ == "__main__":
    main()

