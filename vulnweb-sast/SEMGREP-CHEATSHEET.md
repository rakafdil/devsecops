# 🚀 Semgrep SAST Command Cheat Sheet

## Quick Start Commands

### 1. Basic Scanning

```bash
# Auto-detect and scan
semgrep --config=auto .

# Scan specific directory
semgrep --config=auto src/

# Scan specific file
semgrep --config=auto src/login.php
```

### 2. Scan with Specific Rulesets

```bash
# PHP security rules
semgrep --config=p/php src/

# OWASP Top 10
semgrep --config=p/owasp-top-ten src/

# Security audit
semgrep --config=p/security-audit src/

# SQL Injection specific
semgrep --config=p/sql-injection src/

# XSS specific
semgrep --config=p/xss src/

# Multiple rulesets
semgrep --config=p/php --config=p/owasp-top-ten src/
```

### 3. Output Formats

```bash
# JSON output
semgrep --config=auto src/ --json

# Save to file
semgrep --config=auto src/ --json --output=report.json

# SARIF format (for GitHub/GitLab)
semgrep --config=auto src/ --sarif --output=report.sarif

# JUnit XML format
semgrep --config=auto src/ --junit-xml --output=report.xml

# Text output (default)
semgrep --config=auto src/ --text
```

### 4. Filtering Results

```bash
# Only show ERROR severity
semgrep --config=auto src/ --severity ERROR

# Show ERROR and WARNING
semgrep --config=auto src/ --severity ERROR --severity WARNING

# Exclude INFO level
semgrep --config=auto src/ --exclude-rule "*.INFO"

# Filter by rule ID
semgrep --config=auto src/ --include "php.lang.security.*"
```

### 5. Advanced Options

```bash
# Verbose output
semgrep --config=auto src/ --verbose

# Very verbose (debug mode)
semgrep --config=auto src/ -vv

# Show only findings count
semgrep --config=auto src/ --quiet

# Disable metrics collection
semgrep --config=auto src/ --metrics=off

# Include metrics
semgrep --config=auto src/ --metrics=on
```

### 6. Scan Performance

```bash
# Limit memory usage (in MB)
semgrep --config=auto src/ --max-memory 2000

# Set timeout per file (in seconds)
semgrep --config=auto src/ --timeout 30

# Number of parallel jobs
semgrep --config=auto src/ --jobs 4

# Scan only git-tracked files
semgrep --config=auto src/ --use-git-ignore
```

### 7. Exclude Files/Directories

```bash
# Exclude pattern
semgrep --config=auto src/ --exclude="*.min.php"

# Exclude multiple patterns
semgrep --config=auto src/ --exclude="vendor/" --exclude="*.test.php"

# Use .semgrepignore file
semgrep --config=auto src/ --exclude-from=.semgrepignore

# Don't use .gitignore
semgrep --config=auto src/ --no-git-ignore
```

### 8. Custom Rules

```bash
# Use local rule file
semgrep --config=rules.yml src/

# Use multiple rule files
semgrep --config=rules1.yml --config=rules2.yml src/

# Mix local and registry rules
semgrep --config=p/php --config=custom-rules.yml src/

# Use rules from URL
semgrep --config=https://example.com/rules.yml src/
```

### 9. Autofix

```bash
# Show available autofixes
semgrep --config=auto src/ --autofix

# Apply autofixes automatically
semgrep --config=auto src/ --autofix --dryrun=false

# Dry run (show what would be fixed)
semgrep --config=auto src/ --autofix --dryrun
```

### 10. CI/CD Integration

```bash
# CI mode (exit with code 1 if findings)
semgrep --config=auto src/ --error

# Fail on any findings
semgrep --config=auto src/ --strict

# Baseline mode (only new findings)
semgrep --config=auto src/ --baseline=baseline.json

# Generate baseline
semgrep --config=auto src/ --json --output=baseline.json
```

## 🎯 Real-World Examples

### Complete Security Scan

```bash
# Comprehensive security scan with detailed output
semgrep \
  --config=p/php \
  --config=p/owasp-top-ten \
  --config=p/security-audit \
  src/ \
  --json \
  --output=full-scan-report.json \
  --verbose
```

### Quick Vulnerability Check

```bash
# Fast scan for critical issues only
semgrep \
  --config=p/php \
  src/ \
  --severity ERROR \
  --quiet
```

### Generate Report for Management

```bash
# Scan and generate multiple report formats
semgrep \
  --config=p/php \
  --config=p/owasp-top-ten \
  src/ \
  --json --output=report.json \
  --sarif --output=report.sarif \
  --junit-xml --output=report.xml
```

### Pre-commit Hook Scan

```bash
# Scan only staged files
git diff --cached --name-only --diff-filter=ACM | \
  grep '\.php$' | \
  xargs semgrep --config=auto --quiet
```

### Continuous Monitoring

```bash
# Watch mode (experimental)
semgrep --config=auto src/ --watch

# Scheduled scan with timestamp
semgrep --config=auto src/ --json \
  --output="scan-$(date +%Y%m%d-%H%M%S).json"
```

## 📊 Analysis Commands

### View Scan Statistics

```bash
# Show parsing and scanning time
semgrep --config=auto src/ --time

# Show matched rules
semgrep --config=auto src/ --verbose | grep "Ran.*rules"

# Count findings by severity
semgrep --config=auto src/ --json | \
  jq '[.results[].extra.severity] | group_by(.) | map({severity: .[0], count: length})'
```

### Filter and Sort Results

```bash
# Get only ERROR findings
semgrep --config=auto src/ --json | \
  jq '.results[] | select(.extra.severity == "ERROR")'

# Group by file
semgrep --config=auto src/ --json | \
  jq 'group_by(.path) | map({file: .[0].path, count: length})'

# Sort by line number
semgrep --config=auto src/ --json | \
  jq '.results | sort_by(.start.line)'
```

## 🔧 Troubleshooting

```bash
# Check Semgrep version
semgrep --version

# Validate rule file
semgrep --validate --config=rules.yml

# Test single rule
semgrep --config=rules.yml --test

# Debug mode
semgrep --config=auto src/ --debug

# Clear cache
rm -rf ~/.semgrep/cache
```

## 🐳 Docker Commands

```bash
# Run with Docker
docker run --rm -v "${PWD}:/src" returntocorp/semgrep semgrep --config=auto /src

# Interactive mode
docker run --rm -it -v "${PWD}:/src" returntocorp/semgrep bash

# Specific version
docker run --rm -v "${PWD}:/src" returntocorp/semgrep:1.140.0 semgrep --config=auto /src
```

## 🔄 GitHub Actions Integration

```yaml
# .github/workflows/semgrep.yml
name: Semgrep SAST

on: [push, pull_request]

jobs:
  semgrep:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Run Semgrep
        uses: returntocorp/semgrep-action@v1
        with:
          config: >-
            p/php
            p/owasp-top-ten
            p/security-audit
          
      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: semgrep.sarif
```

## 💡 Pro Tips

### Create Aliases

```bash
# Add to ~/.zshrc or ~/.bashrc

# Quick scan
alias ss='semgrep --config=auto'

# PHP security scan
alias sphp='semgrep --config=p/php --config=p/owasp-top-ten'

# Critical findings only
alias scrit='semgrep --config=auto --severity ERROR'

# JSON output
alias sjson='semgrep --config=auto --json'
```

### Create Scan Script

```bash
#!/bin/bash
# scan.sh - Comprehensive security scan

echo "🔍 Starting security scan..."

semgrep \
  --config=p/php \
  --config=p/owasp-top-ten \
  --config=p/security-audit \
  src/ \
  --json \
  --output="scan-$(date +%Y%m%d).json" \
  --verbose

echo "✅ Scan complete! Report saved."
```

### Pre-commit Hook

```bash
# .git/hooks/pre-commit
#!/bin/bash

echo "Running Semgrep security scan..."

semgrep --config=auto --severity ERROR src/

if [ $? -ne 0 ]; then
    echo "❌ Security issues found! Fix them before committing."
    exit 1
fi

echo "✅ No critical security issues found."
exit 0
```

## 📚 Rule Registries

### Popular Rulesets

| Registry | Description | Command |
|----------|-------------|---------|
| `p/php` | PHP security rules | `--config=p/php` |
| `p/owasp-top-ten` | OWASP Top 10 | `--config=p/owasp-top-ten` |
| `p/security-audit` | General security | `--config=p/security-audit` |
| `p/sql-injection` | SQL injection | `--config=p/sql-injection` |
| `p/xss` | Cross-site scripting | `--config=p/xss` |
| `p/secrets` | Secret detection | `--config=p/secrets` |
| `p/jwt` | JWT vulnerabilities | `--config=p/jwt` |
| `p/insecure-transport` | HTTP issues | `--config=p/insecure-transport` |
| `p/command-injection` | Command injection | `--config=p/command-injection` |

### Browse Rules

```bash
# Open Semgrep Registry in browser
open https://semgrep.dev/r

# Search for PHP rules
open https://semgrep.dev/r?lang=php

# OWASP rules
open https://semgrep.dev/r?category=security
```

## 🆘 Help Commands

```bash
# General help
semgrep --help

# Subcommand help
semgrep scan --help
semgrep login --help

# List all available options
semgrep --help-all

# Show version info
semgrep --version

# Check for updates
semgrep --check-for-updates
```

---

**📖 Full Documentation**: https://semgrep.dev/docs  
**🎮 Playground**: https://semgrep.dev/playground  
**💬 Community**: https://go.semgrep.dev/slack
