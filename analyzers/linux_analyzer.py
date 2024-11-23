import matplotlib
from analyzers.system_analyzer import SystemAnalyzer
from datetime import datetime
matplotlib.use('Agg')
from rich.console import Console
console = Console()

class LinuxAnalyzer(SystemAnalyzer):
    def collect_event_logs(self):
        logs = []
        log_files = ['/var/log/auth.log', '/var/log/syslog', '/var/log/kern.log']
        for log_file in log_files:
            try:
                with open(log_file, 'r') as file:
                    for line in file:
                        match = re.match(r'^([A-Za-z]+\s+\d+\s+\d+:\d+:\d+)\s+(\w+)\s+(\w+):\s+(.*)$', line)
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
                console.print(f"[bold red]Log file {log_file} not found.[/bold red]")
        return logs

    def collect_network_activity(self):
        logs = []
        network_log_file = '/var/log/syslog'
        try:
            with open(network_log_file, 'r') as file:
                for line in file:
                    if 'network' in line.lower() or 'eth0' in line.lower() or 'wlan' in line.lower() or 'dhcp' in line.lower():
                        match = re.match(r'^([A-Za-z]+\s+\d+\s+\d+:\d+:\d+)\s+(\w+)\s+(\w+):\s+(.*)$', line)
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
            console.print(f"[bold red]Network log file {network_log_file} not found.[/bold red]")
        return logs