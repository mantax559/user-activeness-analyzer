import platform
if platform.system() == "Windows":
    import win32evtlog
    import win32evtlogutil
from datetime import datetime
from analyzers.system_analyzer import SystemAnalyzer
from rich.console import Console

console = Console()


class WindowsAnalyzer(SystemAnalyzer):
    def __init__(self, log_types=None):
        if log_types is None:
            log_types = ['Security', 'System', 'Application']
        self.log_types = log_types

    def collect_event_logs(self):
        logs = []
        failed_login_attempts = 0
        reboot_events = 0

        for log_type in self.log_types:
            server = 'localhost'  # Local machine
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

            try:
                handle = win32evtlog.OpenEventLog(server, log_type)
                win32evtlog.GetNumberOfEventLogRecords(handle)  # Ensure the log is accessible

                events = win32evtlog.ReadEventLog(handle, flags, 0)
                while events:
                    for event in events:
                        try:
                            logs.append(self._process_event(event, log_type, failed_login_attempts, reboot_events))
                        except Exception as e:
                            console.print(f"[bold red]Error processing an event: {e}[/bold red]")

                    events = win32evtlog.ReadEventLog(handle, flags, 0)

                win32evtlog.CloseEventLog(handle)
            except Exception as e:
                console.print(f"[bold red]Error reading {log_type} log: {e}[/bold red]")

        return logs

    @staticmethod
    def _process_event(event, log_type, failed_login_attempts, reboot_events):
        """Process a single event and extract relevant details."""
        event_time = datetime.fromtimestamp(event.TimeGenerated.timestamp())
        source = event.SourceName
        event_id = event.EventID & 0xFFFF  # Extract the actual event ID
        message = win32evtlogutil.SafeFormatMessage(event, log_type)
        computer_name = event.ComputerName

        if "failed" in message.lower() or event_id in [4625, 529]:  # Failed login events
            failed_login_attempts += 1

        if "reboot" in message.lower() or event_id in [6006, 6005]:  # Reboot events
            reboot_events += 1

        return {
            'TimeGenerated': event_time,
            'SourceName': source,
            'Message': message,
            'ComputerName': computer_name,
            'FailedLoginAttempts': failed_login_attempts,
            'RebootEvents': reboot_events
        }

    def collect_network_activity(self):
        console.print("[bold yellow]Network activity collection is not implemented for WindowsAnalyzer.[/bold yellow]")
        return []

    def collect_bash_logs(self):
        console.print("[bold yellow]Bash logs are not applicable for WindowsAnalyzer.[/bold yellow]")
        return []