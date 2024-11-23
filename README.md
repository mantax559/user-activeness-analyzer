# UserActivenessAnalyzer

A tool for analyzing both Windows and Linux user activity patterns through system logs, with visual insights for forensics and behavior profiling.

## Overview

**UserActivenessAnalyzer** is designed to collect and analyze both Windows Event Viewer logs and Linux system logs, as well as shell command histories, to provide insights into user behavior. The tool's primary use case is to visualize terminal command usage and system activities, which is particularly useful for digital forensic investigations and user behavior profiling. It supports both Windows and Linux environments, making it versatile for various analysis scenarios.

## Features

- **Cross-Platform Support**: Works on both Windows and Linux systems to collect and analyze logs.
- **Log Parsing**: Collects and processes log files from `/var/log/auth.log`, `.bash_history`, and Windows Event Viewer to analyze user activity.
- **User Behavior Profiling**: Identifies patterns in command usage, login times, and session durations.
- **Visualization**: Generates charts and graphs for easy understanding of user behavior, including login frequency.

## Tech Stack

- **Python**: Main language for log parsing, data analysis, and visualization.
- **Pandas**: For handling and visualizing data efficiently.
- **Matplotlib**: For creating charts and graphs to visualize user activities.
- **Rich**: For formatted console output (optional, can be removed if not supported).

## Getting Started

### Prerequisites

- Python 3.8+
- Administrator privileges for running the script in Windows (required to access Event Viewer logs)

### Installation

1. **Clone the repository**:
   
   ```bash
   git clone https://github.com/mantax559/user-activeness-analyzer.git
   cd user-activeness-analyzer
   ```

2. **Set up virtual environment** (optional but recommended):

   ```bash
   python -m venv venv
   
   # On Windows:
   venv\Scripts\activate
   
   # On Linux/macOS:
   source venv/bin/activate
   ```

3. **Install dependencies**:

   ```bash
   pip install -r requirements_win.txt (if Windows)
   pip install -r requirements_macos.txt (if macOS/Linux)
   ```

### Running the Analysis

1. **Ensure administrator privileges**:
   - If you are on Windows, run your command prompt or PyCharm as an administrator, otherwise you may receive a permissions error when trying to read the Event Viewer logs.

2. **Run the tool**:

   ```bash
   python main.py
   ```

3. **View Visualizations**:
   - The results, including graphs of user activity, will be saved in the `data/` directory.

## Usage

This tool is useful for:
- **Digital Forensics**: Investigate user activities and detect anomalies in behavior.
- **User Profiling**: Understand typical user activities and command usage trends.
- **Education**: Demonstrate system activity analysis on Windows or Linux systems.

## Project Structure

- **main.py**: Main script to run the analysis.
- **data/**: Directory where visualizations and analysis results are stored.

## Notes

- To successfully access Windows Event Viewer logs, the script must be run with elevated permissions (administrator privileges). If using an IDE such as PyCharm, ensure that you run the IDE as an administrator.
- For Linux, the script analyzes `/var/log/auth.log` and `.bash_history` files, which may require root permissions for access. Ensure you run the script with sufficient privileges to read these logs.
- The **Rich** library is used for better console formatting, but it is optional. If you encounter issues, you can modify the script to use simple `print` statements instead.

## Future Enhancements

- Expand compatibility to additional log sources (e.g., other Linux distributions or macOS).
- Add more sophisticated user activity analysis techniques, including anomaly detection.
- Integrate real-time log monitoring and alerting capabilities.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE.md) for more details.

## Contributing

Contributions are welcome! Please fork this repository and submit a pull request if you'd like to add features or improve the tool.

## Contact

For any inquiries or issues, please open an issue in this repository or contact the authors.

---

Thank you for using **UserActivenessAnalyzer**! We hope this helps make user activity analysis easier and more effective.
