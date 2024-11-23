from rich.console import Console
from rich.table import Table
from rich import box

console = Console()

class NetworkActivityProcessor:
    def analyze(self, df):
        network_logs = df[df['Message'].str.contains('network|eth0|wlan|dhcp|netstat', case=False, na=False)]
        network_activity_count = network_logs['ComputerName'].value_counts()

        table = Table(title="Network Activity Frequencies", box=box.SIMPLE_HEAVY)
        table.add_column("User", no_wrap=True)
        table.add_column("Network Activity Count")

        for user, count in network_activity_count.items():
            table.add_row(user, str(count))

        console.print(table)
        return network_activity_count
