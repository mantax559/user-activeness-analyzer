import socket
import matplotlib
import re
from analyzers.system_analyzer import SystemAnalyzer
from datetime import datetime
matplotlib.use('Agg')
from rich.console import Console
import subprocess
console = Console()

class MacOSAnalyzer(SystemAnalyzer):
    def collect_event_logs(self, predicate='eventMessage contains "network"'):
        logs = []
        process = None
        computer_name = socket.gethostname()
        try:
            command = f"sudo log show --predicate '{predicate}' --info --start '2024-11-23 21:30:00'"
            process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, stderr = process.communicate(timeout=30)
            if process.returncode != 0:
                console.print(f"[bold red]Error reading macOS logs: {stderr}[/bold red]")
                return logs
            for line in stdout.splitlines():
                match = re.match(r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{6}[+-]\d{4})\s+\S+\s+\S+\s+\S+\s+(\d+)\s+\S+\s+(\S+):\s+(.*)$', line)
                if match:
                    logs.append({
                        'TimeGenerated': datetime.strptime(match.group(1), '%Y-%m-%d %H:%M:%S.%f%z'),
                        'ProcessID': match.group(2),
                        'ComputerName': computer_name,
                        'SourceName': match.group(3),
                        'Message': match.group(4),
                    })
                else:
                    console.print(f"[bold yellow]No match for line:[/bold yellow] {line}")
        except Exception as e:
            console.print(f"[bold red]Error collecting macOS logs: {e}[/bold red]")
        return logs

    def collect_network_activity(self):
        return self.collect_event_logs(predicate='eventMessage contains "network" OR eventMessage contains "TCP" OR eventMessage contains "UDP"')

