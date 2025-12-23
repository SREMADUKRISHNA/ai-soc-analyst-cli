import argparse
import sys
import os

# Add src to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from rich.console import Console
from rich.table import Table
from utils.banner import print_banner
from ingestion.loader import LogIngestor
from detection.engine import DetectionEngine
from ai_engine.risk_engine import RiskEngine
from reporting.writer import ReportGenerator

console = Console()

def get_base_dir():
    # Helper to find project root
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def load_and_detect():
    base_dir = get_base_dir()
    log_dir = os.path.join(base_dir, 'logs')
    
    with console.status("[bold green]Ingesting logs..."):
        loader = LogIngestor(log_dir)
        df = loader.load_logs()
    
    if df.empty:
        console.print("[red]No logs found to analyze![/red]")
        return None, []

    with console.status("[bold green]Running detection rules..."):
        detector = DetectionEngine()
        alerts = detector.run_detection(df)
        
    return df, alerts

def cmd_scan():
    df, alerts = load_and_detect()
    if df is None: return

    if not alerts:
        console.print("[green]No threats detected. System Clean.[/green]")
        return

    table = Table(title=f"Detected Threats ({len(alerts)})")
    table.add_column("ID", style="cyan")
    table.add_column("Timestamp", style="magenta")
    table.add_column("Severity", style="red")
    table.add_column("Rule", style="yellow")
    table.add_column("Source IP")

    for alert in alerts:
        table.add_row(
            alert['id'],
            str(alert['timestamp']),
            alert['severity'],
            alert['rule'],
            alert['source_ip']
        )
    
    console.print(table)

def cmd_analyze():
    df, alerts = load_and_detect()
    if df is None: return

    if not alerts:
        console.print("[green]No threats detected.[/green]")
        return

    with console.status("[bold blue]Running AI Risk Engine..."):
        risk_engine = RiskEngine()
        enriched_alerts = risk_engine.enrich_alerts(alerts, df)

    table = Table(title="AI-Enhanced Threat Analysis")
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Severity", style="red")
    table.add_column("Rule", style="yellow")
    table.add_column("AI Insight", style="italic green")

    for alert in enriched_alerts:
        sev_style = "bold red" if alert['severity'] == "CRITICAL" else "red"
        table.add_row(
            alert['id'],
            f"[{sev_style}]{alert['severity']}[/{sev_style}]",
            alert['rule'],
            alert.get('ai_analysis', 'N/A')
        )
    
    console.print(table)

def cmd_rca(alert_id):
    df, alerts = load_and_detect()
    if df is None: return

    # We need enriched alerts for accurate RCA
    risk_engine = RiskEngine()
    enriched_alerts = risk_engine.enrich_alerts(alerts, df)
    
    rca_text = risk_engine.perform_rca(alert_id, enriched_alerts, df)
    
    console.print(f"[bold]Root Cause Analysis for {alert_id}[/bold]")
    console.print(rca_text, style="white")

def cmd_report():
    df, alerts = load_and_detect()
    if df is None: return

    risk_engine = RiskEngine()
    enriched_alerts = risk_engine.enrich_alerts(alerts, df)
    
    # Generate RCA for all critical/high alerts
    rca_texts = []
    for alert in enriched_alerts:
        if alert['severity'] in ['High', 'CRITICAL']:
            text = risk_engine.perform_rca(alert['id'], enriched_alerts, df)
            rca_texts.append(text)
            
    base_dir = get_base_dir()
    output_dir = os.path.join(base_dir, 'output')
    writer = ReportGenerator(output_dir)
    report_path = writer.save_report(enriched_alerts, rca_texts)
    
    console.print(f"[bold green]Report generated successfully at:[/bold green] {report_path}")

def main():
    print_banner()
    
    parser = argparse.ArgumentParser(description="VSMK-AI-SOC CLI Tool")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # scan
    subparsers.add_parser("scan", help="Scan logs for basic threats")
    
    # analyze
    subparsers.add_parser("analyze", help="Deep analysis with AI enrichment")
    
    # rca
    rca_parser = subparsers.add_parser("rca", help="Perform Root Cause Analysis on specific alert")
    rca_parser.add_argument("--id", required=True, help="Alert ID to analyze")
    
    # report
    subparsers.add_parser("report", help="Generate full incident report")
    
    args = parser.parse_args()
    
    if args.command == "scan":
        cmd_scan()
    elif args.command == "analyze":
        cmd_analyze()
    elif args.command == "rca":
        cmd_rca(args.id)
    elif args.command == "report":
        cmd_report()
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
