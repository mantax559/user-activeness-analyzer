from rich.console import Console
from rich.table import Table
from rich import box

console = Console()

class BashProcessor:
    def analyze(self, df):
        bash_logs = df[df['SourceName'].str.contains('bash', case=False, na=False)].copy()
        console.print(f"[bold blue]Bash logs found: {len(bash_logs)}[/bold blue]")

        command_counts = bash_logs['ComputerName'].value_counts()

        bash_logs['User'] = bash_logs['Message'].str.extract(r'(?i)(\w+) executed')
        command_types = bash_logs['Message'].str.extract(r'(?i)(ls|cd|cat|mkdir|rm|touch|chmod|chown|echo|sudo|grep)').fillna('other')
        command_type_counts = command_types[0].value_counts()

        table1 = Table(title="Command Execution by Computer", box=box.SIMPLE_HEAVY)
        table1.add_column("Computer Name", no_wrap=True)
        table1.add_column("Command Count", justify="right")
        for computer, count in command_counts.items():
            table1.add_row(computer, str(count))
        console.print(table1)

        table2 = Table(title="Command Types and Counts", box=box.SIMPLE_HEAVY)
        table2.add_column("Command Type", no_wrap=True)
        table2.add_column("Count", justify="right")
        for command_type, count in command_type_counts.items():
            table2.add_row(command_type, str(count))
        console.print(table2)

        return command_counts, command_type_counts
