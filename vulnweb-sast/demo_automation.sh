#!/bin/bash
# Demo Script untuk Semgrep Automation
# Author: DevSecOps Team
# Date: October 26, 2025

echo "╔══════════════════════════════════════════════════════════════════════╗"
echo "║           SEMGREP AUTOMATION - DEMO SCRIPT                           ║"
echo "╚══════════════════════════════════════════════════════════════════════╝"
echo ""

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Function to print colored output
print_step() {
    echo -e "${BLUE}==>${NC} $1"
}

print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

# Check if Python is installed
print_step "Checking Python installation..."
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version)
    print_success "Python installed: $PYTHON_VERSION"
else
    print_error "Python 3 not found. Please install Python 3."
    exit 1
fi

# Check if Semgrep is installed
print_step "Checking Semgrep installation..."
if command -v semgrep &> /dev/null; then
    SEMGREP_VERSION=$(semgrep --version)
    print_success "Semgrep installed: $SEMGREP_VERSION"
else
    print_error "Semgrep not found. Installing..."
    pip3 install semgrep
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "                          DEMO SCENARIOS"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Demo 1: Quick Scan
echo "📌 DEMO 1: Quick Scan"
print_step "Running quick scan with auto configuration..."
python3 semgrep_automation.py --quick
print_success "Quick scan completed!"
echo ""
read -p "Press Enter to continue..."
echo ""

# Demo 2: Generate HTML Report
echo "📌 DEMO 2: Generate HTML Report"
print_step "Running scan with HTML report generation..."
python3 semgrep_automation.py --quick --html
print_success "HTML report generated!"
print_warning "Opening HTML report in browser..."
# Open HTML report (works on macOS)
if [[ "$OSTYPE" == "darwin"* ]]; then
    LATEST_REPORT=$(ls -t reports/report_*.html | head -1)
    if [ -f "$LATEST_REPORT" ]; then
        open "$LATEST_REPORT"
        print_success "Report opened: $LATEST_REPORT"
    fi
fi
echo ""
read -p "Press Enter to continue..."
echo ""

# Demo 3: Baseline Creation
echo "📌 DEMO 3: Create Security Baseline"
print_step "Creating baseline from current scan..."
python3 semgrep_automation.py --quick --baseline
print_success "Baseline created!"
if [ -f "reports/baseline.json" ]; then
    BASELINE_SIZE=$(wc -l < reports/baseline.json)
    print_success "Baseline contains $BASELINE_SIZE lines"
fi
echo ""
read -p "Press Enter to continue..."
echo ""

# Demo 4: Comprehensive Scan
echo "📌 DEMO 4: Comprehensive Scan with Multiple Configs"
print_step "Running comprehensive scan (this may take a while)..."
python3 semgrep_automation.py --comprehensive --html --markdown
print_success "Comprehensive scan completed!"
echo ""
read -p "Press Enter to continue..."
echo ""

# Demo 5: Severity Filtering
echo "📌 DEMO 5: Filter by Severity (ERROR only)"
print_step "Running scan with ERROR severity filter..."
python3 semgrep_automation.py --quick --severity ERROR --markdown
print_success "Filtered scan completed!"
echo ""
read -p "Press Enter to continue..."
echo ""

# Demo 6: Full Scan
echo "📌 DEMO 6: Full Scan with All Report Types"
print_step "Running full scan with all report formats..."
python3 semgrep_automation.py --full
print_success "Full scan completed!"
echo ""

# Summary
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "                          DEMO SUMMARY"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

print_success "All demos completed successfully!"
echo ""
echo "Generated files in reports/ directory:"
ls -lh reports/ | tail -n +2 | awk '{print "  - " $9 " (" $5 ")"}'
echo ""

echo "📚 Available Commands:"
echo "  • Quick scan:           python3 semgrep_automation.py --quick"
echo "  • HTML report:          python3 semgrep_automation.py --quick --html"
echo "  • Markdown report:      python3 semgrep_automation.py --quick --markdown"
echo "  • Create baseline:      python3 semgrep_automation.py --baseline"
echo "  • Compare with baseline: python3 semgrep_automation.py --diff"
echo "  • Full scan:            python3 semgrep_automation.py --full"
echo "  • Comprehensive:        python3 semgrep_automation.py --comprehensive --html"
echo "  • Custom config:        python3 semgrep_automation.py -c p/owasp-top-ten"
echo "  • Filter severity:      python3 semgrep_automation.py --quick --severity ERROR"
echo ""

echo "📖 Documentation:"
echo "  • Tutorial:             SAST-SEMGREP-TUTORIAL.md"
echo "  • Full Report:          SAST-REPORT.md"
echo "  • Quick Summary:        SCAN-SUMMARY.md"
echo "  • Cheatsheet:           SEMGREP-CHEATSHEET.md"
echo "  • Automation Guide:     SEMGREP-AUTOMATION-README.md"
echo ""

print_success "Demo completed! Happy scanning! 🔐"
echo ""
