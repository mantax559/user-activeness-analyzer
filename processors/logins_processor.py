import pandas as pd
from rich.console import Console
from rich.table import Table
from rich import box

console = Console()

class LoginsProcessor:
    def analyze(self, df):
        logins = df[df['Message'].str.contains('session opened|login|auth', case=False, na=False)]
        logins_count = logins['ComputerName'].value_counts()
        session_durations = logins.groupby('ComputerName')['TimeGenerated'].apply(lambda x: x.diff().mean())

        table = Table(title="Login Frequencies", box=box.SIMPLE_HEAVY)
        table.add_column("User", no_wrap=True)
        table.add_column("Login Count")
        table.add_column("Average Session Duration")

        for user in logins_count.index:
            count = logins_count[user]
            duration = session_durations[user] if pd.notna(session_durations[user]) else "N/A"
            table.add_row(user, str(count), str(duration))

        console.print(table)
        return logins_count, session_durations
