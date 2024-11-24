# UserActivenessAnalyzer

A comprehensive tool for analyzing user activity on Windows and Linux systems through logs, with visual insights for digital forensics and behavior profiling.

## Overview

**UserActivenessAnalyzer** helps analyze user behavior by collecting, processing, and visualizing system logs. It supports both Windows and Linux platforms, making it versatile for digital forensics, user profiling, and educational purposes. Key features include terminal command usage tracking, login times analysis, and network activity visualization.

## Features

- **Cross-Platform Support**: Works seamlessly on Windows and Linux systems.
- **Log Parsing**:
  - Analyzes Linux logs like `/var/log/auth.log`, `/var/log/syslog`, `.bash_history`.
  - Processes Windows Event Viewer logs, including Security, System, and Application logs.
- **User Profiling**: Detects patterns in login times, command execution, and session durations.
- **Anomalies Detection**: Flags unusual activity, such as late-night logins.
- **Network Activity Analysis**: Tracks network-related events and categorizes them.
- **Visualization**: Generates informative charts to represent activity trends and anomalies.
- **Simulation Mode**: Easily test the tool with sample log data.

## Tech Stack

- **Python**: Core language for log parsing, data analysis, and visualization.
- **Pandas**: Efficient data manipulation and analysis.
- **Matplotlib**: Used for creating detailed visualizations.
- **Rich**: For enhanced console output with tables and formatted messages.

## Simulation Mode for Easier Setup

### What's Simulation Mode?
- **Enabled by default**: `SIMULATION_MODE` is set to `True`.
- **Test Data**: Utilizes logs from the `test_data/` directory for simulation.
- **Real Data**: Switch to analyzing real logs by setting `SIMULATION_MODE` to `False`.

### How to Configure
1. Open `main.py`.
2. Change the `SIMULATION_MODE` constant to `True` (simulation) or `False` (real logs).
3. Save the file and restart the tool.

### Why Simulation Mode?
- Allows testing without real log files.
- Simplifies setup on virtual machines.
- Ideal for debugging and learning.

## Setup Instructions

### 1. System Requirements
- Python 3.7 or higher.
- Administrative privileges on Windows.
- Sufficient permissions to access system logs on Linux.

### 2. Install Dependencies

1. **Clone the repository**:
   ```bash
   git clone https://github.com/mantax559/user-activeness-analyzer.git
   cd user-activeness-analyzer
   ```

2. **Setup a virtual environment (recommended)**:
   ```bash
   python -m venv venv
   
   # On Windows:
   venv\Scripts\activate
   
   # On Linux:
   source venv/bin/activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements_windows.txt  # For Windows
   pip install -r requirements_linux.txt  # For Linux
   ```

4. **Run the tool**:
   Ensure proper permissions:
   - On Windows: Run your terminal or IDE as Administrator to access Event Viewer logs.
   - On Linux: Run the script with sufficient privileges to read `/var/log/auth.log` and `.bash_history`.

5. **Run the analysis**:
   ```bash
   python main.py
   ```

6. **View results**:
   Visualizations and processed logs are saved in the `data/` directory.

## Usage

This tool is useful for:
- **Digital Forensics**: Investigate user activity and detect behavior anomalies.
- **User Profiling**: Understand patterns in command usage and login times.
- **Education**: Demonstrate system activity analysis on Windows or Linux.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE.md) for more details.

## Contributing

Contributions are welcome! Please fork this repository and submit a pull request to add features or improve the tool.

## Contact

For inquiries or issues, please open an issue in this repository or contact the authors.

---

Thank you for using **UserActivenessAnalyzer**! We hope this helps make user activity analysis easier and more effective.
