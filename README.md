# UserActivenessAnalyzer

A simple tool for analyzing user activity on Windows and Linux systems through logs, with visual insights for forensics and behavior profiling.

## Overview

**UserActivenessAnalyzer** helps you analyze user behavior by collecting and visualizing system logs. It works on both Windows and Linux, making it useful for digital forensics and user profiling. The tool focuses on terminal command usage, login times, and system activities.

## Features

- **Cross-Platform Support**: Works on Windows and Linux.
- **Log Parsing**: Analyzes logs like `/var/log/auth.log`, `.bash_history`, and Windows Event Viewer logs.
- **User Profiling**: Identifies patterns in login times, command usage, and session lengths.
- **Visualization**: Generates graphs and charts for easy analysis of user behavior.

## Tech Stack

- **Python**: For log parsing, data analysis, and visualization.
- **Pandas**: For efficient data handling.
- **Matplotlib**: For creating charts to visualize activity.
- **Rich**: For formatted console output (optional).

## Simulation Mode for Easier Setup

If you're struggling to set up the application on a VirtualBox machine:

Our app comes with a **Simulation Mode** to make your life easier while you're getting things running. Here's how it works:

### What's Simulation Mode?
- **Enabled by default**: The constant `SIMULATION_MODE` is set to `True`.
- **Test Data**: When enabled, the app will use data from the `test_data/` directory (so you don’t need real logs to get started).
- **Real Data**: If you’re ready to switch to actual log files, just set `SIMULATION_MODE` to `False` in the configuration.

### How to Check/Change the Mode 🛠️
1. Open the main.py file where `SIMULATION_MODE` is defined.
2. Change the constant to True or False
3. Save the file and restart the application.

### Why Use Simulation Mode?
- Avoids headaches when setting up on a virtual machine.
- Helps you test the app’s functionality without needing real-world data right away.
- Perfect for learning and debugging before going live.

So go ahead, use Simulation Mode to get started hassle-free, and feel confident when you're ready to switch to real data.

## Setup Instructions

### 1. Set up Ubuntu on VirtualBox

1. Download and install [VirtualBox](https://www.virtualbox.org/).
2. Download the [Ubuntu 24 LTS ISO](https://ubuntu.com/download/desktop).
3. Create a new virtual machine in VirtualBox with:
   - **4GB RAM** minimum.
   - **1 processor**.
4. Install Ubuntu using the ISO file and follow the on-screen instructions.

### 2. Install Dependencies

1. **Clone the repository**:

   ```bash
   git clone https://github.com/mantax559/user-activeness-analyzer.git
   cd user-activeness-analyzer

2. **Setup virtual environment (recommended)**
```
   python -m venv venv
   # On Windows:
   venv\Scripts\activate
   # On Linux:
   source venv/bin/activate
```

3. **Installl dependencies**
```
pip install -r requirements_linux.txt # For Linux
pip install -r requirements_windows.txt # For Windows
```

4. **Run the tool**
Ensure proper permissions. On Windows, run your terminal or IDE as Administrator to access Event Viewer logs.
On Linux, run the script with sufficient privileges to read /var/log/auth.log and .bash_history.

5. **Run the analysis**
python main.py

6. **View results**
Visualizations are saved in data/ directory

## Usage

This tool is useful for:

* Digital Forensics: Investigate user activity and detect behavior anomalies.
* User Profiling: Understand patterns in command usage and login times.
* Education: Demonstrate system activity analysis on Windows or Linux.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE.md) for more details.

## Contributing

Contributions are welcome! Please fork this repository and submit a pull request if you'd like to add features or improve the tool.

## Contact

For any inquiries or issues, please open an issue in this repository or contact the authors.

---

Thank you for using **UserActivenessAnalyzer**! We hope this helps make user activity analysis easier and more effective
