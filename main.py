import os
import re
import platform
import pandas as pd
from datetime import datetime
import matplotlib.pyplot as plt
import json
import matplotlib
from rich.console import Console
from rich.table import Table
from rich import box

# Ensure matplotlib works in environments without GUI
matplotlib.use('Agg')

# Create a Console instance for rich output
console = Console()

# Import platform-specific modules
if platform.system() == "Windows":
    import win32evtlog


# Ensure the 'data' directory exists
def ensure_data_directory():
    data_dir = "data"
    if not os.path.exists(data_dir):
        os.makedirs(data_dir)
    return data_dir


# Function to collect logs from Windows Event Viewer
def collect_event_logs_windows(log_type='Security'):
    logs = []
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
        win32evtlog.CloseEventLog(handle)
    return logs


# Function to collect logs from Linux log files
def collect_event_logs_linux(log_file='/var/log/auth.log'):
    logs = []
    try:
        with open(log_file, 'r') as file:
            for line in file:
                # Parse the log line using regex to extract useful fields
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


# Function to extract command history from Linux
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


# Function to clean and structure the collected data
def clean_data(logs):
    df = pd.DataFrame(logs)
    if 'TimeGenerated' in df.columns:
        df['TimeGenerated'] = pd.to_datetime(df['TimeGenerated'], errors='coerce')
        df.dropna(subset=['TimeGenerated'], inplace=True)
    return df


# Function to analyze user activities
def analyze_logs(df):
    # Calculate login frequency and activity duration
    logins = df[df['Message'].str.contains('session opened|login|auth', case=False, na=False)]
    logins_count = logins['ComputerName'].value_counts()

    # Display login frequencies in a table
    table = Table(title="Login Frequencies", box=box.SIMPLE_HEAVY)
    table.add_column("User", no_wrap=True)
    table.add_column("Login Count")

    for user, count in logins_count.items():
        table.add_row(user, str(count))

    console.print(table)
    return logins_count


# Function to visualize user activities
def visualize_activity(logins_count, output_dir):
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
    else:
        console.print("[bold yellow]No login data available to visualize.[/bold yellow]")


# Main function
def main():
    # Ensure the 'data' directory exists
    data_dir = ensure_data_directory()

    # Determine the platform
    system_platform = platform.system()

    # Step 1: Collect event logs based on the platform
    logs = []
    if system_platform == "Windows":
        logs = collect_event_logs_windows()
    elif system_platform == "Linux":
        # Collect system logs
        logs = collect_event_logs_linux()
        # Collect command history
        command_logs = collect_command_history_linux()
        logs.extend(command_logs)
    else:
        console.print(f"[bold red]Unsupported platform: {system_platform}[/bold red]")
        return

    # Step 2: Clean and prepare data for analysis
    df = clean_data(logs)

    # Step 3: Analyze data
    if not df.empty:
        console.print("Analyzing Logs")
        login_counts = analyze_logs(df)
    else:
        console.print("[bold yellow]No logs available for analysis.[/bold yellow]")
        return

    # Step 4: Visualize the analysis results
    if not login_counts.empty:
        console.print("Visualizing Activity")
        visualize_activity(login_counts, data_dir)
    else:
        console.print("[bold yellow]No login data available for visualization.[/bold yellow]")

    # Save collected data as JSON for future use
    log_path = os.path.join(data_dir, 'logs.json')
    with open(log_path, 'w') as f:
        json.dump(logs, f, default=str)
    console.print(f"[bold green]Logs saved to '{log_path}'[/bold green]")


if __name__ == "__main__":
    main()
