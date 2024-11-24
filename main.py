import os
import json
import platform
import pandas as pd
from analyzers.windows_analyzer import WindowsAnalyzer
from analyzers.linux_analyzer import LinuxAnalyzer
from processors.logins_processor import LoginsProcessor
from processors.network_activity_processor import NetworkActivityProcessor
from processors.anomalies_processor import AnomaliesProcessor
from processors.bash_processor import BashProcessor
from processors.visualizer import Visualizer
from rich.console import Console

console = Console()
SIMULATION_MODE = True


def ensure_data_directory():
    data_dir = "data"
    os.makedirs(data_dir, exist_ok=True)
    return data_dir


def get_system_analyzer():
    if SIMULATION_MODE:
        test_data_dir = "test_data"
        return LinuxAnalyzer([
            os.path.join(test_data_dir, 'auth_real.log'),
            os.path.join(test_data_dir, 'syslog_real.log'),
            os.path.join(test_data_dir, 'kern.log'),
            os.path.join(test_data_dir, '.bash_history')
        ])

    system_platform = platform.system()
    if system_platform == "Windows":
        return WindowsAnalyzer()
    if system_platform == "Linux":
        return LinuxAnalyzer()
    raise NotImplementedError(f"Unsupported platform: {system_platform}")


def clean_data(logs):
    df = pd.DataFrame(logs)
    if 'TimeGenerated' in df.columns:
        df['TimeGenerated'] = pd.to_datetime(df['TimeGenerated'], errors='coerce')
        df.dropna(subset=['TimeGenerated'], inplace=True)
    return df


def main():
    data_dir = ensure_data_directory()

    analyzer = get_system_analyzer()
    logs = analyzer.collect_event_logs() + analyzer.collect_network_activity()

    if hasattr(analyzer, 'collect_bash_logs'):
        logs += analyzer.collect_bash_logs()

    df = clean_data(logs)
    if df.empty:
        console.print("[bold yellow]No logs available for analysis.[/bold yellow]")
        return

    logins_processor = LoginsProcessor()
    network_activity_processor = NetworkActivityProcessor()
    anomalies_processor = AnomaliesProcessor()
    bash_processor = BashProcessor()
    visualizer = Visualizer()

    login_counts, session_durations, failed_logins, reboot_events = logins_processor.analyze(df)
    network_activity_count, activity_types = network_activity_processor.analyze(df)
    command_counts, command_type_counts = bash_processor.analyze(df)
    anomalies_processor.analyze(df)

    visualizer.visualize_activity(login_counts, session_durations, failed_logins, reboot_events, data_dir)
    visualizer.visualize_network_activity(network_activity_count, activity_types, data_dir)
    visualizer.visualize_bash_activity(command_counts, command_type_counts, data_dir)

    log_path = os.path.join(data_dir, 'logs.json')
    with open(log_path, 'w') as f:
        json.dump(str(logs), f)
    console.print(f"[bold green]Logs saved to '{log_path}'[/bold green]")


if __name__ == "__main__":
    main()
