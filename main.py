import os
import re
import platform
import pandas as pd
from datetime import datetime
import matplotlib.pyplot as plt
import json
import subprocess

# Import platform-specific modules
if platform.system() == "Windows":
    import win32evtlog
    import win32evtlogutil
    import win32api


# Function to collect logs from Windows Event Viewer
def collect_event_logs_windows(log_type='Security'):
    logs = []
    handle = win32evtlog.OpenEventLog(None, log_type)
    flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    try:
        events = win32evtlog.ReadEventLog(handle, flags, 0)
        while events:
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
            events = win32evtlog.ReadEventLog(handle, flags, 0)
    except Exception as e:
        print(f"Error reading Windows event logs: {e}")
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
        print(f"Log file {log_file} not found. Make sure you have the correct path and permissions.")
    return logs


# Function to clean and structure the collected data
def clean_data(logs):
    df = pd.DataFrame(logs)
    if 'TimeGenerated' in df.columns:
        df['TimeGenerated'] = pd.to_datetime(df['TimeGenerated'], errors='coerce')
        df = df.dropna(subset=['TimeGenerated'])
    return df


# Function to analyze user activities
def analyze_logs(df):
    # Calculate login frequency and activity duration
    print("Dataframe head for inspection:")
    print(df.head())  # Patikrinkite pirmas kelias eilutes, kad matytumėte, ar yra naudingų duomenų

    logins = df[df['Message'].str.contains('login|session|auth', case=False, na=False)]
    logins_count = logins['ComputerName'].value_counts()

    print("Login Frequencies:")
    print(logins_count)

    return logins_count


# Function to visualize user activities
def visualize_activity(logins_count):
    if not logins_count.empty:
        logins_count.plot(kind='bar', title='Login Frequency per User')
        plt.xlabel('User')
        plt.ylabel('Login Count')
        plt.xticks(rotation=45)
        plt.tight_layout()
        plt.savefig('login_frequency.png')
        plt.show()
    else:
        print("No login data available to visualize.")


# Function to extract command history from Linux
def collect_command_history_linux(command_history_file='~/.bash_history'):
    logs = []
    expanded_path = os.path.expanduser(command_history_file)
    try:
        with open(expanded_path, 'r') as file:
            for line in file:
                if line.strip():
                    logs.append({'Command': line.strip(), 'TimeGenerated': datetime.now()})
    except FileNotFoundError:
        print(
            f"Command history file {command_history_file} not found. Make sure you have the correct path and permissions.")
    return logs


# Main function
def main():
    # Determine the platform
    system_platform = platform.system()

    # Step 1: Collect event logs based on the platform
    if system_platform == "Windows":
        logs = collect_event_logs_windows()
    elif system_platform == "Linux":
        # Collect system logs
        logs = collect_event_logs_linux()
        # Collect command history
        command_logs = collect_command_history_linux()
        logs.extend(command_logs)
    else:
        print(f"Unsupported platform: {system_platform}")
        return

    # Step 2: Clean and prepare data for analysis
    df = clean_data(logs)

    # Step 3: Analyze data
    if not df.empty:
        login_counts = analyze_logs(df)
    else:
        print("No logs available for analysis.")
        return

    # Step 4: Visualize the analysis results
    if not login_counts.empty:
        visualize_activity(login_counts)
    else:
        print("No login data available for visualization.")

    # Save collected data as JSON for future use
    with open('logs.json', 'w') as f:
        json.dump(logs, f, default=str)


if __name__ == "__main__":
    main()
