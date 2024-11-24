from rich.console import Console
from rich.table import Table
from rich import box
import pandas as pd

console = Console()

class NetworkActivityProcessor:
    def analyze(self, df):
        keywords = ['network', 'eth0', 'wlan', 'dhcp', 'netstat', 'connection', 'disconnected', 'reconnected']
        network_logs = df[df['Message'].str.contains('|'.join(keywords), case=False, na=False)]

        network_activity_count = network_logs['ComputerName'].value_counts().fillna(0)

        table = Table(title="Network Activity Analysis", box=box.SIMPLE_HEAVY)
        table.add_column("Computer Name", no_wrap=True)
        table.add_column("Network Activity Count", justify="right")

        for computer, count in network_activity_count.items():
            table.add_row(computer, str(count))
        console.print(table)

        activity_types = network_logs['Message'].str.extract(r'(?i)(connected|disconnected|dhcp|interface|link|error)').fillna("Unknown")
        activity_type_counts = activity_types[0].value_counts().fillna(0)

        table2 = Table(title="Activity Type Frequencies", box=box.SIMPLE_HEAVY)
        table2.add_column("Activity Type", no_wrap=True)
        table2.add_column("Count", justify="right")

        for activity, count in activity_type_counts.items():
            table2.add_row(activity, str(count))
        console.print(table2)

        return network_activity_count, activity_type_counts