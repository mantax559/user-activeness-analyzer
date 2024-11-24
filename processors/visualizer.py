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

    def visualize_network_activity(self, network_activity_count, activity_types, output_dir):
        if not network_activity_count.empty:
            plt.figure(figsize=(10, 6))
            network_activity_count.plot(kind='bar', title='Network Activity Frequency per Computer')
            plt.xlabel('Computer Name')
            plt.ylabel('Activity Count')
            plt.xticks(rotation=45)
            plt.tight_layout()
            output_path1 = os.path.join(output_dir, 'network_activity_by_computer.png')
            plt.savefig(output_path1)
            console.print(f"[bold green]Network activity by computer saved as '{output_path1}'[/bold green]")
            plt.close()
        else:
            console.print("[bold yellow]No network activity data available for computers.[/bold yellow]")
        if not activity_types.empty:
            plt.figure(figsize=(10, 6))
            activity_types.plot(kind='bar', title='Activity Type Frequency')
            plt.xlabel('Activity Type')
            plt.ylabel('Count')
            plt.xticks(rotation=45)
            plt.tight_layout()
            output_path2 = os.path.join(output_dir, 'activity_type_distribution.png')
            plt.savefig(output_path2)
            console.print(f"[bold green]Activity type distribution saved as '{output_path2}'[/bold green]")
            plt.close()
        else:
            console.print("[bold yellow]No activity type data available to visualize.[/bold yellow]")

    def visualize_bash_activity(self, command_counts, user_activity, failed_commands, command_type_counts, output_dir):
        if not command_counts.empty:
            plt.figure(figsize=(10, 6))
            command_counts.plot(kind='bar', title='Command Execution by Computer')
            plt.xlabel('Computer Name')
            plt.ylabel('Command Count')
            plt.xticks(rotation=45)
            plt.tight_layout()
            output_path1 = os.path.join(output_dir, 'command_execution_by_computer.png')
            plt.savefig(output_path1)
            console.print(f"[bold green]Command execution by computer saved as '{output_path1}'[/bold green]")
            plt.close()
        else:
            console.print("[bold yellow]No command execution data available to visualize.[/bold yellow]")

        if not user_activity.empty:
            plt.figure(figsize=(10, 6))
            user_activity.plot(kind='bar', title='User Activity')
            plt.xlabel('User')
            plt.ylabel('Command Count')
            plt.xticks(rotation=45)
            plt.tight_layout()
            output_path2 = os.path.join(output_dir, 'user_activity.png')
            plt.savefig(output_path2)
            console.print(f"[bold green]User activity visualization saved as '{output_path2}'[/bold green]")
            plt.close()
        else:
            console.print("[bold yellow]No user activity data available to visualize.[/bold yellow]")

        if not failed_commands.empty:
            plt.figure(figsize=(10, 6))
            failed_commands['ComputerName'].value_counts().plot(kind='bar', title='Failed Commands by Computer')
            plt.xlabel('Computer Name')
            plt.ylabel('Failed Command Count')
            plt.xticks(rotation=45)
            plt.tight_layout()
            output_path3 = os.path.join(output_dir, 'failed_commands_by_computer.png')
            plt.savefig(output_path3)
            console.print(f"[bold green]Failed commands visualization saved as '{output_path3}'[/bold green]")
            plt.close()
        else:
            console.print("[bold yellow]No failed command data available to visualize.[/bold yellow]")
        if not command_type_counts.empty:
            plt.figure(figsize=(10, 6))
            command_type_counts.plot(kind='bar', title='Failed Commands by Computer')
            plt.xlabel('Command Type')
            plt.ylabel('Count')
            plt.xticks(rotation=45)
            plt.tight_layout()
            output_path3 = os.path.join(output_dir, 'command_type_counts.png')
            plt.savefig(output_path3)
            console.print(f"[bold green]Command type counts visualization saved as '{output_path3}'[/bold green]")
            plt.close()
        else:
            console.print("[bold yellow]No command type counts data available to visualize.[/bold yellow]")