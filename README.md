# 🔐 File Integrity Monitor (FIM)

A medium-level defensive cybersecurity project written in Python that detects unauthorized or unexpected changes to files by comparing their **SHA-256 cryptographic hashes** against a trusted baseline.

## 🎯 Why this project?

File integrity monitoring is used in defensive security to identify changes to important files. A changed hash does not automatically mean an attack occurred; it means the file content is different and should be investigated.

## ✨ Features

- Creates a SHA-256 baseline for a directory
- Detects **added** files
- Detects **modified** files
- Detects **deleted** files
- Stores the baseline as JSON
- Uses Python's standard library only
- Handles unreadable files without stopping the scan

## 🧰 Technologies

- Python 3
- SHA-256 (`hashlib`)
- JSON
- `pathlib`
- `argparse`
- File-system monitoring concepts

## 🚀 Getting Started

### 1. Clone the repository

```bash
git clone https://github.com/irsad-ali404/file-integrity-monitor.git
cd file-integrity-monitor
```

### 2. Create a test directory

Create a directory such as `lab/` and put a few harmless text files inside it.

### 3. Create the baseline

```bash
python fim.py baseline lab
```

This creates `.fim_baseline.json` containing the trusted hashes.

### 4. Test detection

Edit a file inside `lab/`, add another file, or delete one.

Then run:

```bash
python fim.py scan lab
```

You should see `[ADDED]`, `[MODIFIED]`, or `[DELETED]` results.

## 🧪 Example

```text
FIM scan: /home/user/fim-lab
------------------------------------------------------------

[ADDED] 1 file(s)
  + new_note.txt

[MODIFIED] 1 file(s)
  * important.txt

[DELETED] 1 file(s)
  - old_note.txt

[!] Review these changes and verify whether they were authorized.
```

## 🛡️ Security Notes

This project is designed for **defensive and authorized use**. It does not exploit systems or bypass access controls.

For a real deployment, the baseline should be protected from unauthorized modification. A stronger version could use a signed baseline, centralized logging, alerting, and scheduled scans.

## 🔮 Possible Future Improvements

- Scheduled monitoring
- Email or webhook alerts
- Digital signatures for the baseline
- SQLite event history
- Configurable exclusion rules
- Windows Event Log / Linux syslog integration
- Unit tests and CI

## 📚 Learning Outcomes

This project demonstrates:

- Cryptographic hashing
- File-system traversal
- Baseline comparison
- Change detection
- Defensive security concepts
- Python CLI development
- Basic security logging concepts

## ⚠️ Disclaimer

Use this project only on files and systems you own or have explicit permission to monitor.
