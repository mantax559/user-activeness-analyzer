import os
import matplotlib.pyplot as plt
from rich.console import Console

console = Console()

class Visualizer:
    def visualize_activity(self, logins_count, session_durations, failed_logins, reboot_events, output_dir):
        self._plot_data(logins_count, 'Login Frequency per User', 'User', 'Login Count', 'login_frequency.png', output_dir)
        self._plot_data(session_durations, 'Average Session Duration per User', 'User', 'Average Duration (in seconds)', 'session_duration.png', output_dir)
        self._plot_data(failed_logins, 'Failed Login Attempts per User', 'User', 'Failed Login Attempts', 'failed_logins.png', output_dir)
        self._plot_data(reboot_events, 'Reboot Events per User', 'User', 'Reboot Events', 'reboot_events.png', output_dir)

        if all(data.empty for data in [logins_count, session_durations, failed_logins, reboot_events]):
            console.print("[bold yellow]No data available to visualize.[/bold yellow]")

    def visualize_network_activity(self, network_activity_count, activity_types, output_dir):
        self._plot_data(network_activity_count, 'Network Activity Frequency per Computer', 'Computer Name', 'Activity Count', 'network_activity_by_computer.png', output_dir)
        self._plot_data(activity_types, 'Activity Type Frequency', 'Activity Type', 'Count', 'activity_type_distribution.png', output_dir)

    def visualize_bash_activity(self, command_counts, command_type_counts, output_dir):
        self._plot_data(command_counts, 'Command Execution by Computer', 'Computer Name', 'Command Count', 'command_execution_by_computer.png', output_dir)
        self._plot_data(command_type_counts, 'Command Type Counts', 'Command Type', 'Count', 'command_type_counts.png', output_dir)

    def _plot_data(self, data, title, xlabel, ylabel, filename, output_dir):
        if not data.empty:
            plt.figure(figsize=(10, 6))
            data.plot(kind='bar', title=title)
            plt.xlabel(xlabel)
            plt.ylabel(ylabel)
            plt.xticks(rotation=45)
            plt.tight_layout()
            output_path = os.path.join(output_dir, filename)
            plt.savefig(output_path)
            console.print(f"[bold green]{title} saved as '{output_path}'[/bold green]")
            plt.close()
        else:
            console.print(f"[bold yellow]No data available for {title.lower()}.[/bold yellow]")
