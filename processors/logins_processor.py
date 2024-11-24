from rich.console import Console
from rich.table import Table
from rich import box
import pandas as pd

console = Console()

class LoginsProcessor:
    def analyze(self, df):
        logins = df[df['Message'].str.contains('session opened|login|auth', case=False, na=False)]
        logins_count = logins['ComputerName'].value_counts()
        session_durations = logins.groupby('ComputerName')['TimeGenerated'].apply(lambda x: x.diff().mean())
        failed_logins = df.groupby('ComputerName')['FailedLoginAttempts'].max()
        reboot_events = df.groupby('ComputerName')['RebootEvents'].max()

        table = Table(title="Login Frequencies", box=box.SIMPLE_HEAVY)
        table.add_column("User", no_wrap=True)
        table.add_column("Login Count")
        table.add_column("Average Session Duration")
        table.add_column("Failed Login Attempts")
        table.add_column("Reboot Events")

        for user in logins_count.index:
            count = logins_count[user]
            duration = session_durations[user] if pd.notna(session_durations[user]) else "N/A"
            failed = failed_logins.get(user, 0)
            reboot = reboot_events.get(user, 0)
            table.add_row(user, str(count), str(duration), str(failed), str(reboot))

        console.print(table)

        return logins_count, session_durations, failed_logins, reboot_events
