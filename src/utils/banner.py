from rich.console import Console
from rich.panel import Panel
from rich.text import Text

def print_banner():
    console = Console()
    
    ascii_art = """
██╗   ██╗███████╗███╗   ███╗██╗  ██╗       █████╗ ██╗       ███████╗ ██████╗  ██████╗ 
██║   ██║██╔════╝████╗ ████║██║ ██╔╝      ██╔══██╗██║       ██╔════╝██╔═══██╗██╔════╝ 
██║   ██║███████╗██╔████╔██║█████╔╝ █████╗███████║██║ █████╗███████╗██║   ██║██║      
╚██╗ ██╔╝╚════██║██║╚██╔╝██║██╔═██╗ ╚════╝██╔══██║██║ ╚════╝╚════██║██║   ██║██║      
 ╚████╔╝ ███████║██║ ╚═╝ ██║██║  ██╗      ██║  ██║██║       ███████║╚██████╔╝╚██████╗ 
  ╚═══╝  ╚══════╝╚═╝     ╚═╝╚═╝  ╚═╝      ╚═╝  ╚═╝╚═╝       ╚══════╝ ╚═════╝  ╚═════╝ 
    """
    
    title = Text("AI-Powered SOC Analyst & Automated RCA", style="bold cyan")
    author = Text("Author: VSMK-Security | v1.0.0 Production Build", style="dim white")
    
    panel = Panel(
        Text.from_markup(f"[green]{ascii_art}[/green]") + Text("\n") + title + Text("\n") + author,
        border_style="green",
        expand=False
    )
    
    console.print(panel)

if __name__ == "__main__":
    print_banner()
