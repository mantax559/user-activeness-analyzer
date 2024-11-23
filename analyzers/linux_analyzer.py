import matplotlib
from analyzers.system_analyzer import SystemAnalyzer
from datetime import datetime
matplotlib.use('Agg')
from rich.console import Console
console = Console()
import re

class LinuxAnalyzer(SystemAnalyzer):
    def __init__(self, log_files=['/var/log/auth.log', '/var/log/syslog', '/var/log/kern.log']):
        self.log_files = log_files
        self.network_log_file = log_files[1]

    def collect_event_logs(self):
        logs = []
        for log_file in self.log_files:
            try:
                with open(log_file, 'r') as file:
                    for line in file:
                        match = re.match(r'^([A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\w+)\s+sshd\[\d+\]:\s+(.*)$', line)
                        if match:
                            log_date_str = match.group(1)
                            try:
                                log_date = datetime.strptime(log_date_str, '%b %d %H:%M:%S').replace(year=datetime.now().year)
                            except ValueError:
                                print("ERR: could not resolve log data", log_date_str)
                                continue

                            message = match.group(3).lower()

                            logs.append({
                                'TimeGenerated': log_date,
                                'SourceName': "sshd",
                                'Message': match.group(3),
                                'ComputerName': match.group(2)
                            })

            except FileNotFoundError:
                console.print(f"[bold red]Log file {log_file} not found.[/bold red]")

        return logs

    def collect_network_activity(self):
        logs = []
        try:
            with open(self.network_log_file, 'r') as file:
                for line in file:
                    if 'network' in line.lower() or 'eth0' in line.lower() or 'wlan' in line.lower() or 'dhcp' in line.lower():
                        match = re.match(r'^([A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\w+)\s+(\w+):\s+(.*)$', line)
                        if match:
                            log_date_str = match.group(1)
                            try:
                                log_date = datetime.strptime(log_date_str, '%b %d %H:%M:%S').replace(year=datetime.now().year)
                            except ValueError:
                                continue
                            logs.append({
                                'TimeGenerated': log_date,
                                'SourceName': match.group(3),
                                'Message': match.group(4),
                                'ComputerName': match.group(2)
                            })
        except FileNotFoundError:
            console.print(f"[bold red]Network log file {self.network_log_file} not found.[/bold red]")

        return logs