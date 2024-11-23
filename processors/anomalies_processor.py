from rich.console import Console

console = Console()

class AnomaliesProcessor:
    def analyze(self, df):
        anomalies = df[(df['TimeGenerated'].dt.hour < 6) | (df['TimeGenerated'].dt.hour > 22)]
        console.print(f"[bold yellow]Number of logins at unusual hours: {len(anomalies)}[/bold yellow]")
        return anomalies
