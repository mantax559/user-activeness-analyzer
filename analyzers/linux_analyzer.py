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
        failed_login_attempts = 0
        reboot_events = 0

        log_pattern = re.compile(
            r'^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}\+00:00)\s+(?P<hostname>[\w\-.]+)\s+(?P<service>\S+): (?P<message>.+)$'
        )

        for log_file in self.log_files:
            try:
                with open(log_file, 'r') as file:
                    for line in file:
                        match = log_pattern.match(line)
                        if match:
                            log_data = match.groupdict()
                            timestamp = log_data["timestamp"]
                            hostname = log_data["hostname"]
                            service = log_data["service"]
                            message = log_data["message"]

                            try:
                                log_date = datetime.strptime(timestamp, '%Y-%m-%dT%H:%M:%S.%f+00:00')
                            except ValueError:
                                console.print(f"[bold red]ERR: Invalid timestamp format: {timestamp}[/bold red]")
                                continue

                            if "authentication failure" in message.lower() or "failed password" in message.lower():
                                failed_login_attempts += 1

                            if "reboot" in message.lower():
                                reboot_events += 1

                            logs.append({
                                'TimeGenerated': log_date,
                                'SourceName': service,
                                'Message': message,
                                'ComputerName': hostname,
                                'FailedLoginAttempts': failed_login_attempts,
                                'RebootEvents': reboot_events
                            })

            except FileNotFoundError:
                console.print(f"[bold red]Log file {log_file} not found.[/bold red]")
        return logs

    def collect_network_activity(self):
        logs = []

        log_pattern = re.compile(
            r'^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}\+00:00)\s+'
            r'(?P<hostname>[\w\-.]+)\s+(?P<source>\S+):\s+(?P<message>.+)$'
        )

        try:
            with open(self.network_log_file, 'r') as file:
                for line in file:
                    if any(keyword in line.lower() for keyword in ["network", "eth0", "wlan", "dhcp"]):
                        match = log_pattern.match(line)
                        if match:
                            log_data = match.groupdict()

                            try:
                                log_date = datetime.strptime(log_data["timestamp"], '%Y-%m-%dT%H:%M:%S.%f+00:00')
                            except ValueError:
                                console.print(f"[bold red]Invalid timestamp format: {log_data['timestamp']}[/bold red]")
                                continue

                            logs.append({
                                'TimeGenerated': log_date,
                                'SourceName': log_data["source"],
                                'Message': log_data["message"],
                                'ComputerName': log_data["hostname"],
                            })
        except FileNotFoundError:
            console.print(f"[bold red]Network log file {self.network_log_file} not found.[/bold red]")
        except Exception as e:
            console.print(f"[bold red]An error occurred: {e}[/bold red]")
        print("Will return logs", logs)
        return logs