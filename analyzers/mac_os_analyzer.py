import matplotlib
import re
from analyzers.system_analyzer import SystemAnalyzer
from datetime import datetime
matplotlib.use('Agg')
from rich.console import Console
import subprocess
console = Console()

class MacOSAnalyzer(SystemAnalyzer):
    def collect_event_logs(self, predicate='eventMessage contains "network"', show_info=True):
        logs = []
        process = None
        try:
            command = f"log show --predicate '{predicate}' --info --start '2024-11-23 21:10:00'"
            process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, stderr = process.communicate(timeout=30)
            if process.returncode != 0:
                console.print(f"[bold red]Error reading macOS logs: {stderr}[/bold red]")
                return logs
            for line in stdout.splitlines():
                match = re.match(r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}.\d{3}) (\S+) (\S+)\[(\d+)] <\S+>: (.+)$', line)
                if match:
                    logs.append({
                        'TimeGenerated': datetime.strptime(match.group(1), '%Y-%m-%d %H:%M:%S.%f'),
                        'ComputerName': match.group(2),
                        'SourceName': match.group(3),
                        'Message': match.group(5),
                    })
        except Exception as e:
            console.print(f"[bold red]Error collecting macOS logs: {e}[/bold red]")
        return logs

    def collect_network_activity(self):
        return self.collect_event_logs(predicate='eventMessage contains "network" OR eventMessage contains "TCP" OR eventMessage contains "UDP"')

