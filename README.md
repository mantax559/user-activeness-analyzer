# UserActivenessAnalyzer

A tool for analyzing Linux user activity patterns through system logs, with visual insights for forensics and behavior profiling.

## Overview

**UserActivenessAnalyzer** is designed to collect and analyze Linux system logs and shell command histories, aiming to provide insights into user behavior. The tool's primary use case is to visualize terminal command usage and system activities, which is particularly useful for digital forensic investigations and user behavior profiling. The analysis is performed in a controlled virtual machine environment to ensure reproducibility and easy deployment.

## Features

- **Log Parsing**: Collects and processes log files from `/var/log/auth.log`, `/var/log/syslog` and `.bash_history` to analyze user activity.
- **User Behavior Profiling**: Identifies patterns in command usage, login times and session durations.
- **Anomaly Detection**: Highlights unusual activity such as rare commands or login anomalies.
- **Visualization**: Generates interactive charts and graphs for easy understanding of user behavior.

## Tech Stack

- **Python**: Main language for log parsing, data analysis and visualization.
- **Pandas**: For handling and visualizing data efficiently.
- **Bash**: Assists in log extraction and data preprocessing.
- **Oracle VirtualBox**: Emulates Linux environment for reproducible results.
- **Canonical Ubuntu**: Target Linux distribution for analysis.

## Getting Started

### Prerequisites

- Python 3.8+
- Oracle VirtualBox
- Ubuntu (or any Debian-based Linux system)

### Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/mantax559/UserActivenessAnalyzer.git
   cd UserActivenessAnalyzer
   ```
2. **Set up virtual environment** (optional but recommended):
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```
3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

### Running the Analysis

1. **Collect log data**:
   - Extract necessary log files (`/var/log/auth.log`, `/var/log/syslog`, `.bash_history`) from the Linux system you want to analyze.

2. **Run the tool**:
   ```bash
   python analyze.py
   ```

3. **View Visualizations**:
   - The results, including graphs of user activity, will be saved in the `outputs/` directory.

## Usage

This tool is useful for:
- **Digital Forensics**: Investigate user activities and detect anomalies in behavior.
- **User Profiling**: Understand typical user activities and command usage trends.
- **Education**: Demonstrate system activity analysis in a reproducible Linux environment.

## Project Structure

- **analyze.py**: Main script to run the analysis.
- **utils/**: Helper functions for log parsing and data processing.
- **outputs/**: Directory where visualizations and analysis results are stored.
- **requirements.txt**: Python dependencies for the project.

## Future Enhancements

- Expand compatibility to additional Linux distributions beyond Ubuntu.
- Add more sophisticated anomaly detection techniques.
- Integrate real-time log monitoring and alerting capabilities.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for more details.

## Contributing

Contributions are welcome! Please fork this repository and submit a pull request if you'd like to add features or improve the tool.

## Contact

For any inquiries or issues, please open an issue in this repository or contact the authors.

---

Thank you for using **UserActivenessAnalyzer**! We hope this helps make user activity analysis easier and more effective.
