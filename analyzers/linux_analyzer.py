import re
import os
import platform
from datetime import datetime
from rich.console import Console
from analyzers.system_analyzer import SystemAnalyzer

console = Console()

class LinuxAnalyzer(SystemAnalyzer):
    def __init__(self, log_files=None):
        if log_files is None:
            log_files = [
                '/var/log/auth.log',
                '/var/log/syslog',
                '/var/log/kern.log',
                '/home/vboxuser/.bash_history'
            ]
        self.log_files = log_files
        self.network_log_file = log_files[1]
        self.bash_log_file = log_files[-1]

    def collect_event_logs(self):
        logs = []
        failed_login_attempts = 0
        reboot_events = 0

        log_pattern = re.compile(
            r'^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}\+00:00)\s+'
            r'(?P<hostname>[\w\-.]+)\s+(?P<service>\S+):\s+(?P<message>.+)$'
        )

        for log_file in self.log_files:
            logs.extend(self._process_log_file(log_file, log_pattern, failed_login_attempts, reboot_events))
        return logs

    def collect_network_activity(self):
        logs = []

        log_pattern = re.compile(
            r'^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}\+00:00)\s+'
            r'(?P<hostname>[\w\-.]+)\s+(?P<source>\S+):\s+(?P<message>.+)$'
        )

        logs.extend(self._process_network_logs(log_pattern))
        return logs

    def collect_bash_logs(self):
        logs = []

        try:
            with open(self.bash_log_file, 'r') as file:
                logs = [
                    {
                        'TimeGenerated': datetime.now(),
                        'SourceName': 'bash',
                        'Message': line.strip(),
                        'ComputerName': os.uname().nodename if platform.system() == "Linux" else "N/A",
                    }
                    for line in file if line.strip()
                ]
        except FileNotFoundError:
            console.print(f"[bold red]Bash history file {self.bash_log_file} not found.[/bold red]")
        except Exception as e:
            console.print(f"[bold red]An error occurred while reading bash history: {e}[/bold red]")

        return logs

    def _process_log_file(self, log_file, log_pattern, failed_login_attempts, reboot_events):
        logs = []
        try:
            with open(log_file, 'r') as file:
                for line in file:
                    match = log_pattern.match(line)
                    if match:
                        log_data = match.groupdict()
                        try:
                            log_date = datetime.strptime(log_data["timestamp"], '%Y-%m-%dT%H:%M:%S.%f+00:00')
                        except ValueError:
                            console.print(f"[bold red]ERR: Invalid timestamp format: {log_data['timestamp']}[/bold red]")
                            continue

                        message = log_data["message"].lower()
                        if "authentication failure" in message or "failed password" in message:
                            failed_login_attempts += 1
                        if "reboot" in message:
                            reboot_events += 1

                        logs.append({
                            'TimeGenerated': log_date,
                            'SourceName': log_data["service"],
                            'Message': log_data["message"],
                            'ComputerName': log_data["hostname"],
                            'FailedLoginAttempts': failed_login_attempts,
                            'RebootEvents': reboot_events
                        })
        except FileNotFoundError:
            console.print(f"[bold red]Log file {log_file} not found.[/bold red]")
        return logs

    def _process_network_logs(self, log_pattern):
        logs = []
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
        return logs
