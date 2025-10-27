# 🤖 Semgrep Automation Script

Script Python untuk otomasi Semgrep SAST scanning dengan berbagai fitur canggih.

## 🚀 Features

- ✅ **Multiple Scan Modes**: Quick, comprehensive, baseline, dan diff scan
- ✅ **Auto Report Generation**: HTML, Markdown, dan JSON reports
- ✅ **Baseline Comparison**: Track security improvements over time
- ✅ **Statistics Analysis**: Detailed vulnerability breakdown
- ✅ **CI/CD Ready**: Easy integration dengan pipeline
- ✅ **Configurable**: Multiple configuration options
- ✅ **Beautiful Reports**: Professional HTML reports dengan visualisasi

## 📋 Prerequisites

```bash
# Install Semgrep
pip install semgrep

# Verify installation
semgrep --version
```

## 🎯 Quick Start

### 1. Basic Usage

```bash
# Quick scan dengan auto config
python semgrep_automation.py --quick

# Scan dengan config spesifik
python semgrep_automation.py --config p/php

# Comprehensive scan
python semgrep_automation.py --comprehensive
```

### 2. Generate Reports

```bash
# Generate HTML report
python semgrep_automation.py --quick --html

# Generate Markdown report
python semgrep_automation.py --quick --markdown

# Generate both
python semgrep_automation.py --comprehensive --html --markdown
```

### 3. Baseline Management

```bash
# Create baseline
python semgrep_automation.py --baseline

# Compare with baseline (show only new findings)
python semgrep_automation.py --diff

# Update baseline
python semgrep_automation.py --quick --baseline
```

### 4. Full Scan

```bash
# Full scan dengan semua report types
python semgrep_automation.py --full

# Full scan dengan target dan output custom
python semgrep_automation.py --full --target src/ --output reports/
```

## 📖 Command Reference

### Arguments

| Argument | Short | Description | Example |
|----------|-------|-------------|---------|
| `--target` | `-t` | Target directory | `-t src/` |
| `--output` | `-o` | Output directory | `-o reports/` |
| `--config` | `-c` | Semgrep config | `-c p/owasp-top-ten` |
| `--quick` | `-q` | Quick scan | `-q` |
| `--comprehensive` | - | Multiple configs | `--comprehensive` |
| `--html` | - | Generate HTML | `--html` |
| `--markdown` | - | Generate Markdown | `--markdown` |
| `--baseline` | - | Create baseline | `--baseline` |
| `--diff` | - | Compare with baseline | `--diff` |
| `--full` | - | Full scan + all reports | `--full` |
| `--severity` | - | Filter severity | `--severity ERROR WARNING` |

### Common Configurations

```bash
# PHP Security Scan
python semgrep_automation.py --config p/php --html

# OWASP Top 10 Scan
python semgrep_automation.py --config p/owasp-top-ten --html

# Security Audit
python semgrep_automation.py --config p/security-audit --markdown

# Only ERROR severity
python semgrep_automation.py --quick --severity ERROR
```

## 📊 Output Examples

### Console Output

```
======================================================================
🔐 SEMGREP SAST AUTOMATION
======================================================================
Target: src/
Output: reports/

✓ Semgrep installed: 1.140.0

🔍 Running scan with config: auto
   Command: semgrep --config=auto src/ --json --output=reports/scan_auto_20251026_213000.json
✓ Scan completed. Output saved to: reports/scan_auto_20251026_213000.json

======================================================================
📊 SCAN SUMMARY
======================================================================
Total Findings: 33
  - ERROR:   31
  - WARNING: 2
  - INFO:    0
======================================================================

✅ Scan completed successfully!
```

### HTML Report

Script akan generate HTML report yang cantik dengan:
- Summary statistics dengan cards berwarna
- Tabel findings by file
- Top vulnerabilities by CWE
- Detailed findings dengan syntax highlighting
- Responsive design

### Markdown Report

```markdown
# Semgrep SAST Report

**Generated**: 2025-10-26 21:30:00
**Target**: src/

## Summary

- **Total Findings**: 33
- **Critical (ERROR)**: 31
- **High (WARNING)**: 2
- **Medium (INFO)**: 0

## Findings by File

| File | Count |
|------|-------|
| `src/orders.php` | 10 |
| `src/products.php` | 8 |
...
```

## 🔄 CI/CD Integration

### GitHub Actions

```yaml
name: Security SAST Scan

on: [push, pull_request]

jobs:
  semgrep:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.x'
      
      - name: Install Semgrep
        run: pip install semgrep
      
      - name: Run SAST Scan
        run: |
          python semgrep_automation.py --full
      
      - name: Upload Reports
        uses: actions/upload-artifact@v3
        with:
          name: sast-reports
          path: reports/
```

### GitLab CI

```yaml
semgrep-scan:
  image: python:3.11
  before_script:
    - pip install semgrep
  script:
    - python semgrep_automation.py --full
  artifacts:
    paths:
      - reports/
    expire_in: 30 days
```

### Jenkins Pipeline

```groovy
pipeline {
    agent any
    
    stages {
        stage('SAST Scan') {
            steps {
                sh 'pip install semgrep'
                sh 'python semgrep_automation.py --full'
            }
        }
        
        stage('Archive Reports') {
            steps {
                archiveArtifacts artifacts: 'reports/**', fingerprint: true
            }
        }
    }
}
```

## 📚 Advanced Usage

### Custom Scan Script

```python
from semgrep_automation import SemgrepAutomation

# Initialize
automation = SemgrepAutomation(target_dir="src/", output_dir="reports/")

# Check installation
if not automation.check_semgrep_installed():
    exit(1)

# Run scan
results = automation.run_scan(config="p/php")

# Analyze
stats = automation.analyze_results(results)

# Generate reports
automation.generate_html_report(results, stats)
automation.generate_markdown_report(stats)

# Create baseline
automation.create_baseline(results)
```

### Scheduled Scanning

```bash
# Add to crontab for daily scan
0 2 * * * cd /path/to/project && python semgrep_automation.py --full --html
```

### Baseline Workflow

```bash
# 1. Initial scan and create baseline
python semgrep_automation.py --quick --baseline

# 2. Make code changes
# ... edit code ...

# 3. Check for new vulnerabilities
python semgrep_automation.py --diff

# 4. If acceptable, update baseline
python semgrep_automation.py --quick --baseline
```

## 🎨 Report Features

### HTML Report Includes:

1. **Summary Cards**
   - Total findings
   - Breakdown by severity (ERROR, WARNING, INFO)
   - Color-coded gradient cards

2. **Detailed Tables**
   - Findings by file (sorted by count)
   - Top 10 vulnerabilities by CWE
   - Interactive hover effects

3. **Finding Details**
   - File path and line number
   - Severity indicator
   - Full vulnerability description
   - Color-coded borders

4. **Professional Design**
   - Responsive layout
   - Modern CSS styling
   - Print-friendly

## 🛠️ Troubleshooting

### Semgrep Not Found

```bash
# Install Semgrep
pip install semgrep

# Or using Homebrew (macOS)
brew install semgrep

# Verify
semgrep --version
```

### Permission Errors

```bash
# Make script executable
chmod +x semgrep_automation.py

# Run with python explicitly
python3 semgrep_automation.py --quick
```

### No Results

```bash
# Check target directory exists
ls -la src/

# Try with verbose Semgrep
semgrep --config=auto src/ --verbose

# Check file permissions
chmod -R 755 src/
```

## 📊 Performance Tips

1. **Target Specific Directories**: Don't scan node_modules, vendor, etc.
   ```bash
   python semgrep_automation.py --target src/ --quick
   ```

2. **Use Specific Configs**: More focused, faster scans
   ```bash
   python semgrep_automation.py --config p/php --quick
   ```

3. **Filter by Severity**: Reduce noise
   ```bash
   python semgrep_automation.py --quick --severity ERROR
   ```

## 🔒 Security Best Practices

1. **Run regularly**: Schedule daily/weekly scans
2. **Use baseline**: Track security improvements
3. **Review findings**: Don't ignore warnings
4. **Integrate CI/CD**: Prevent vulnerable code from merging
5. **Update Semgrep**: Keep rules up to date

## 📝 Example Workflow

```bash
# Day 1: Initial scan and baseline
python semgrep_automation.py --comprehensive --html --baseline

# Day 2-7: Development
# ... developers write code ...

# Day 7: Weekly scan
python semgrep_automation.py --diff --html

# Review HTML report
open reports/report_*.html

# If new issues found, fix them
# ... fix vulnerabilities ...

# Rescan to verify fixes
python semgrep_automation.py --quick --html

# Update baseline when satisfied
python semgrep_automation.py --quick --baseline
```

## 🤝 Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create feature branch
3. Test your changes
4. Submit pull request

## 📄 License

MIT License - Free to use for educational and commercial purposes

## 📞 Support

- Issues: Create GitHub issue
- Docs: Check Semgrep documentation
- Community: Join Semgrep Slack

---

**Happy Scanning! 🔐**
