import platform
if platform.system() == "Windows":
    import win32evtlog
import matplotlib
import subprocess
from analyzers.system_analyzer import SystemAnalyzer
from datetime import datetime
matplotlib.use('Agg')
from rich.console import Console
console = Console()

class WindowsAnalyzer(SystemAnalyzer):
    def collect_event_logs(self):
        logs = []
        handle = None
        try:
            handle = win32evtlog.OpenEventLog(None, "Security")
            flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            while events := win32evtlog.ReadEventLog(handle, flags, 0):
                for event in events:
                    logs.append({
                        'EventID': event.EventID,
                        'TimeGenerated': event.TimeGenerated,
                        'SourceName': event.SourceName,
                        'EventType': event.EventType,
                        'EventCategory': event.EventCategory,
                        'ComputerName': event.ComputerName,
                        'Message': " ".join(event.StringInserts) if event.StringInserts else None
                    })
        except Exception as e:
            console.print(f"[bold red]Error reading Windows event logs:[/bold red] {e}")
        finally:
            if handle:
                win32evtlog.CloseEventLog(handle)
        return logs

    def collect_network_activity(self):
        logs = []
        try:
            netstat_output = subprocess.check_output("netstat -an", shell=True, text=True)
            timestamp = datetime.now()
            for line in netstat_output.splitlines():
                if line.strip().startswith("TCP") or line.strip().startswith("UDP"):
                    logs.append({
                        'TimeGenerated': timestamp,
                        'SourceName': 'netstat',
                        'Message': line.strip(),
                        'ComputerName': platform.node()
                    })
        except subprocess.CalledProcessError as e:
            console.print(f"[bold red]Error executing netstat command:[/bold red] {e}")
        return logs
