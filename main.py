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
from analyzers.windows_analyzer import WindowsAnalyzer
from analyzers.linux_analyzer import LinuxAnalyzer
from analyzers.mac_os_analyzer import MacOSAnalyzer

matplotlib.use('Agg')

console = Console()

def get_system_analyzer():
    system_platform = platform.system()
    if system_platform == "Windows":
        return WindowsAnalyzer()
    elif system_platform == "Linux":
        return LinuxAnalyzer()
    elif system_platform == "Darwin":
        return MacOSAnalyzer()
    else:
        raise NotImplementedError(f"Unsupported platform: {system_platform}")

def ensure_data_directory():
    data_dir = "data"
    if not os.path.exists(data_dir):
        os.makedirs(data_dir)
    return data_dir

def clean_data(logs):
    df = pd.DataFrame(logs)
    if 'TimeGenerated' in df.columns:
        df['TimeGenerated'] = pd.to_datetime(df['TimeGenerated'], errors='coerce')
        df.dropna(subset=['TimeGenerated'], inplace=True)
    return df

def main():
    analyzer = get_system_analyzer()
    data_dir = ensure_data_directory()

    logs = analyzer.collect_event_logs()
    network_logs = analyzer.collect_network_activity()
    logs.extend(network_logs)

    df = clean_data(logs)

    if not df.empty:
        console.print("Analyzing Logs")
        login_counts, session_durations = analyze_logs(df)
        network_activity_count = analyze_network_activity(df)
        analyze_anomalies(df)

        console.print("Visualizing Activity")
        visualize_activity(login_counts, session_durations, data_dir)
        visualize_network_activity(network_activity_count, data_dir)

    log_path = os.path.join(data_dir, 'logs.json')
    with open(log_path, 'w') as f:
        json.dump(logs, f, default=str)
    console.print(f"[bold green]Logs saved to '{log_path}'[/bold green]")

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


if __name__ == "__main__":
    main()