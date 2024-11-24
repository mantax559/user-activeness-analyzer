from rich.console import Console
from rich.table import Table
from rich import box
import pandas as pd

console = Console()

class BashProcessor:
    def analyze(self, df):
        bash_logs = df[df['SourceName'].str.contains('bash', case=False, na=False)]
        console.print(f"[bold blue]Bash logs found: {len(bash_logs)}[/bold blue]")

        command_counts = bash_logs['ComputerName'].value_counts()

        bash_logs['User'] = bash_logs['Message'].str.extract(r'(?i)(\w+) executed')

        user_activity = bash_logs['User'].value_counts()

        failed_commands = bash_logs[bash_logs['Message'].str.contains('permission denied', case=False, na=False)]

        table1 = Table(title="Command Execution by Computer", box=box.SIMPLE_HEAVY)
        table1.add_column("Computer Name", no_wrap=True)
        table1.add_column("Command Count", justify="right")
        for computer, count in command_counts.items():
            table1.add_row(computer, str(count))
        console.print(table1)

        table2 = Table(title="User Activity Summary", box=box.SIMPLE_HEAVY)
        table2.add_column("User", no_wrap=True)
        table2.add_column("Command Count", justify="right")
        for user, count in user_activity.items():
            table2.add_row(user, str(count))
        console.print(table2)

        table3 = Table(title="Failed Commands", box=box.SIMPLE_HEAVY)
        table3.add_column("Time", no_wrap=True)
        table3.add_column("Computer Name", no_wrap=True)
        table3.add_column("Message")
        for _, row in failed_commands.iterrows():
            table3.add_row(str(row['TimeGenerated']), row['ComputerName'], row['Message'])
        console.print(table3)

        return command_counts, user_activity, failed_commands
