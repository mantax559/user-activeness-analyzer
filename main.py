import os
import pandas as pd
import platform
from analyzers.windows_analyzer import WindowsAnalyzer
from analyzers.linux_analyzer import LinuxAnalyzer
from analyzers.mac_os_analyzer import MacOSAnalyzer
from processors.logins_processor import LoginsProcessor
from processors.network_activity_processor import NetworkActivityProcessor
from processors.anomalies_processor import AnomaliesProcessor
from processors.visualizer import Visualizer

def ensure_data_directory():
    data_dir = "data"
    if not os.path.exists(data_dir):
        os.makedirs(data_dir)
    return data_dir

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

def clean_data(logs):
    df = pd.DataFrame(logs)
    if 'TimeGenerated' in df.columns:
        df['TimeGenerated'] = pd.to_datetime(df['TimeGenerated'], errors='coerce')
        df.dropna(subset=['TimeGenerated'], inplace=True)
    return df

def main():
    data_dir = ensure_data_directory()

    analyzer = get_system_analyzer()
    logs = analyzer.collect_event_logs()
    network_logs = analyzer.collect_network_activity()
    logs.extend(network_logs)
    df = clean_data(logs)

    logins_processor = LoginsProcessor()
    network_activity_processor = NetworkActivityProcessor()
    anomalies_processor = AnomaliesProcessor()
    visualizer = Visualizer()

    if df.empty:
        print("No logs available for analysis.")
        return
    
    login_counts, session_durations = logins_processor.analyze(df)
    network_activity_count = network_activity_processor.analyze(df)
    anomalies_processor.analyze(df)

    visualizer.visualize_activity(login_counts, session_durations, data_dir)
    visualizer.visualize_network_activity(network_activity_count, data_dir)
    
if __name__ == "__main__":
    main()