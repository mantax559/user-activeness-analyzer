from rich.console import Console

console = Console()

class AnomaliesProcessor:
    def analyze(self, df):
        if 'TimeGenerated' not in df.columns or not hasattr(df['TimeGenerated'], 'dt'):
            console.print("[bold red]The dataframe must have a 'TimeGenerated' column with datetime values.[/bold red]")
            return None
        anomalies = df[(df['TimeGenerated'].dt.hour < 6) | (df['TimeGenerated'].dt.hour > 22)]
        console.print(f"[bold yellow]Number of logins at unusual hours: {len(anomalies)}[/bold yellow]")
        return anomalies
