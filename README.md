# PE File Triage Tool

A Python command-line tool for initial static analysis of Windows PE executables. It identifies potentially suspicious characteristics and generates a structured JSON report for further investigation.

## Features

- SHA-256 file hashing
- PE metadata and section permission analysis
- Imported Windows API inspection
- Detection of potentially suspicious imports and writable-executable sections
- Unusual section name detection
- YARA rule scanning
- Authenticode digital signature checking
- Risk assessment with explanatory reasons
- JSON report generation

## Requirements

- Windows
- Python 3
- `pefile`
- YARA command-line executable

## Setup

Install the Python dependency:

```powershell
pip install pefile
```

Ensure the YARA executable path in `main.py` is correct for your system, and keep the rule file at `rules/basic_suspicious.yar`.

## Usage

Run:

```powershell
python main.py
```

Enter the path to the Windows executable when prompted. The tool prints analysis results and saves a JSON report in the current directory.

## Limitations

This tool performs static analysis only. Its findings are indicators for investigation, not proof that a file is malicious. YARA results depend on the rules provided, and signature status depends on the local Windows environment.

## Disclaimer

Created for educational purposes and authorized malware-analysis research. Analyze untrusted files in an isolated environment.
