import os
import pandas as pd
import matplotlib.pyplot as plt
from rich.console import Console

console = Console()

class Visualizer:
    def visualize_activity(self, logins_count, session_durations, output_dir):
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