import os
import re
import platform
import pandas as pd
from datetime import datetime
import matplotlib.pyplot as plt
import json
import matplotlib
import subprocess
from rich.console import Console
from rich.table import Table
from rich import box

matplotlib.use('Agg')

console = Console()

if platform.system() == "Windows":
    import win32evtlog

def ensure_data_directory():
    data_dir = "data"
    if not os.path.exists(data_dir):
        os.makedirs(data_dir)
    return data_dir

def collect_event_logs_windows(log_type='Security'):
    logs = []
    handle = None
    try:
        handle = win32evtlog.OpenEventLog(None, log_type)
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

def collect_network_activity_windows():
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

def collect_event_logs_linux(log_files=['/var/log/auth.log', '/var/log/syslog', '/var/log/kern.log']):
    logs = []
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
            console.print(f"[bold red]Log file {log_file} not found. Make sure you have the correct path and permissions.[/bold red]")
    return logs

def collect_command_history_linux(command_history_file='~/.bash_history'):
    logs = []
    try:
        expanded_path = os.path.expanduser(command_history_file)
        with open(expanded_path, 'r') as file:
            for line in file:
                if line.strip():
                    logs.append({'Command': line.strip(), 'TimeGenerated': datetime.now()})
    except FileNotFoundError:
        console.print(f"[bold red]Command history file {command_history_file} not found. Make sure you have the correct path and permissions.[/bold red]")
    return logs

# Function to collect network activity logs from Linux
def collect_network_activity_linux(network_log_file='/var/log/syslog'):
    logs = []
    try:
        with open(network_log_file, 'r') as file:
            for line in file:
                # Look for network activity patterns in the syslog
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
        console.print(f"[bold red]Network log file {network_log_file} not found. Make sure you have the correct path and permissions.[/bold red]")
    return logs

def clean_data(logs):
    df = pd.DataFrame(logs)
    if 'TimeGenerated' in df.columns:
        df['TimeGenerated'] = pd.to_datetime(df['TimeGenerated'], errors='coerce')
        df.dropna(subset=['TimeGenerated'], inplace=True)
    return df

def analyze_logs(df):
    logins = df[df['Message'].str.contains('session opened|login|auth', case=False, na=False)]
    logins_count = logins['ComputerName'].value_counts()
    session_durations = logins.groupby('ComputerName')['TimeGenerated'].apply(lambda x: x.diff().mean())

    table = Table(title="Login Frequencies", box=box.SIMPLE_HEAVY)
    table.add_column("User", no_wrap=True)
    table.add_column("Login Count")
    table.add_column("Average Session Duration")

    for user in logins_count.index:
        count = logins_count[user]
        duration = session_durations[user] if pd.notna(session_durations[user]) else "N/A"
        table.add_row(user, str(count), str(duration))

    console.print(table)
    return logins_count, session_durations

def analyze_network_activity(df):
    network_logs = df[df['Message'].str.contains('network|eth0|wlan|dhcp|netstat', case=False, na=False)]
    network_activity_count = network_logs['ComputerName'].value_counts()

    table = Table(title="Network Activity Frequencies", box=box.SIMPLE_HEAVY)
    table.add_column("User", no_wrap=True)
    table.add_column("Network Activity Count")

    for user, count in network_activity_count.items():
        table.add_row(user, str(count))

    console.print(table)
    return network_activity_count

def analyze_anomalies(df):
    anomalies = df[(df['TimeGenerated'].dt.hour < 6) | (df['TimeGenerated'].dt.hour > 22)]
    console.print(f"[bold yellow]Number of logins at unusual hours: {len(anomalies)}[/bold yellow]")
    return anomalies

def visualize_activity(logins_count, session_durations, output_dir):
    if not logins_count.empty:
        plt.figure(figsize=(8, 6))
        logins_count.plot(kind='bar', title='Login Frequency per User')
        plt.xlabel('User')
        plt.ylabel('Login Count')
        plt.xticks(rotation=45)
        plt.tight_layout()
        output_path = os.path.join(output_dir, 'login_frequency.png')
        plt.savefig(output_path)
        console.print(f"[bold green]Visualization saved as '{output_path}'[/bold green]")

        plt.figure(figsize=(8, 6))
        session_durations.plot(kind='bar', title='Average Session Duration per User')
        plt.xlabel('User')
        plt.ylabel('Average Duration (in seconds)')
        plt.xticks(rotation=45)
        plt.tight_layout()
        output_path = os.path.join(output_dir, 'session_duration.png')
        plt.savefig(output_path)
        console.print(f"[bold green]Session duration visualization saved as '{output_path}'[/bold green]")
    else:
        console.print("[bold yellow]No login data available to visualize.[/bold yellow]")

def visualize_command_frequency(command_logs, output_dir):
    if command_logs:
        df_commands = pd.DataFrame(command_logs)
        if 'Command' in df_commands.columns:
            command_counts = df_commands['Command'].value_counts()
            plt.figure(figsize=(10, 6))
            command_counts.head(10).plot(kind='bar', title='Top 10 Commands Used')
            plt.xlabel('Command')
            plt.ylabel('Frequency')
            plt.xticks(rotation=45)
            plt.tight_layout()
            output_path = os.path.join(output_dir, 'command_frequency.png')
            plt.savefig(output_path)
            console.print(f"[bold green]Command frequency visualization saved as '{output_path}'[/bold green]")
        else:
            console.print("[bold yellow]No 'Command' data available to visualize.[/bold yellow]")
    else:
        console.print("[bold yellow]No command data available to visualize.[/bold yellow]")

def visualize_network_activity(network_activity_count, output_dir):
    if not network_activity_count.empty:
        plt.figure(figsize=(10, 6))
        network_activity_count.plot(kind='bar', title='Network Activity Frequency per User')
        plt.xlabel('User')
        plt.ylabel('Network Activity Count')
        plt.xticks(rotation=45)
        plt.tight_layout()
        output_path = os.path.join(output_dir, 'network_activity.png')
        plt.savefig(output_path)
        console.print(f"[bold green]Network activity visualization saved as '{output_path}'[/bold green]")
    else:
        console.print("[bold yellow]No network activity data available to visualize.[/bold yellow]")

def main():
    data_dir = ensure_data_directory()

    system_platform = platform.system()

    logs = []
    command_logs = []
    network_logs = []

    if system_platform == "Windows":
        logs = collect_event_logs_windows()
        network_logs = collect_network_activity_windows()
        logs.extend(network_logs)
    elif system_platform == "Linux" or system_platform == "Darwin":
        logs = collect_event_logs_linux()
        logs.extend(command_logs)
        network_logs = collect_network_activity_linux()
        logs.extend(network_logs)
    else:
        console.print(f"[bold red]Unsupported platform: {system_platform}[/bold red]")
        return

    df = clean_data(logs)

    if not df.empty:
        console.print("Analyzing Logs")
        login_counts, session_durations = analyze_logs(df)
        network_activity_count = analyze_network_activity(df)
        analyze_anomalies(df)
    else:
        console.print("[bold yellow]No logs available for analysis.[/bold yellow]")
        return

    if not login_counts.empty:
        console.print("Visualizing Activity")
        visualize_activity(login_counts, session_durations, data_dir)
        visualize_command_frequency(command_logs, data_dir)
        visualize_network_activity(network_activity_count, data_dir)
    else:
        console.print("[bold yellow]No login data available for visualization.[/bold yellow]")

    log_path = os.path.join(data_dir, 'logs.json')
    with open(log_path, 'w') as f:
        json.dump(logs, f, default=str)
    console.print(f"[bold green]Logs saved to '{log_path}'[/bold green]")

if __name__ == "__main__":
    main()
