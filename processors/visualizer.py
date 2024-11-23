import os
import matplotlib.pyplot as plt
from rich.console import Console

console = Console()

class Visualizer:
    def visualize_activity(self, logins_count, session_durations, failed_logins, reboot_events, output_dir):
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

        if not session_durations.empty:
            plt.figure(figsize=(8, 6))
            session_durations.plot(kind='bar', title='Average Session Duration per User')
            plt.xlabel('User')
            plt.ylabel('Average Duration (in seconds)')
            plt.xticks(rotation=45)
            plt.tight_layout()
            output_path = os.path.join(output_dir, 'session_duration.png')
            plt.savefig(output_path)
            console.print(f"[bold green]Session duration visualization saved as '{output_path}'[/bold green]")
        
        if not failed_logins.empty:
            plt.figure(figsize=(8, 6))
            failed_logins.plot(kind='bar', title='Failed Login Attempts per User')
            plt.xlabel('User')
            plt.ylabel('Failed Login Attempts')
            plt.xticks(rotation=45)
            plt.tight_layout()
            output_path = os.path.join(output_dir, 'failed_logins.png')
            plt.savefig(output_path)
            console.print(f"[bold green]Failed logins visualization saved as '{output_path}'[/bold green]")

        if not reboot_events.empty:
            plt.figure(figsize=(8, 6))
            reboot_events.plot(kind='bar', title='Reboot Events per User')
            plt.xlabel('User')
            plt.ylabel('Reboot Events')
            plt.xticks(rotation=45)
            plt.tight_layout()
            output_path = os.path.join(output_dir, 'reboot_events.png')
            plt.savefig(output_path)
            console.print(f"[bold green]Reboot events visualization saved as '{output_path}'[/bold green]")

        if logins_count.empty and session_durations.empty and failed_logins.empty and reboot_events.empty:
            console.print("[bold yellow]No data available to visualize.[/bold yellow]")

    def visualize_network_activity(self, network_activity_count, output_dir):
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