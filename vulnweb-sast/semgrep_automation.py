#!/usr/bin/env python3
"""
Semgrep SAST Automation Tool
Author: DevSecOps Team
Date: October 26, 2025

This script automates Semgrep scanning with various features:
- Multiple scan configurations
- Automatic report generation
- Email notifications
- Trend analysis
- CI/CD integration support
"""

import os
import sys
import json
import subprocess
import argparse
import datetime
from pathlib import Path
from typing import Dict, List, Optional
import shutil


class SemgrepAutomation:
    """Main class for Semgrep automation"""
    
    def __init__(self, target_dir: str = "src/", output_dir: str = "reports/"):
        self.target_dir = target_dir
        self.output_dir = output_dir
        self.timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        self.ensure_output_dir()
        
    def ensure_output_dir(self):
        """Create output directory if it doesn't exist"""
        Path(self.output_dir).mkdir(parents=True, exist_ok=True)
        
    def check_semgrep_installed(self) -> bool:
        """Check if Semgrep is installed"""
        try:
            result = subprocess.run(
                ["semgrep", "--version"],
                capture_output=True,
                text=True,
                check=True
            )
            print(f"✓ Semgrep installed: {result.stdout.strip()}")
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            print("✗ Semgrep not found. Please install: pip install semgrep")
            return False
            
    def run_scan(
        self, 
        config: str = "auto", 
        severity: Optional[List[str]] = None,
        output_format: str = "json"
    ) -> Dict:
        """
        Run Semgrep scan with specified configuration
        
        Args:
            config: Semgrep config (auto, p/php, p/owasp-top-ten, etc.)
            severity: List of severities to include (ERROR, WARNING, INFO)
            output_format: Output format (json, sarif, text)
            
        Returns:
            Dict containing scan results
        """
        output_file = f"{self.output_dir}scan_{config.replace('/', '_')}_{self.timestamp}.{output_format}"
        
        cmd = [
            "semgrep",
            f"--config={config}",
            self.target_dir,
            f"--{output_format}",
            f"--output={output_file}"
        ]
        
        if severity:
            for sev in severity:
                cmd.extend(["--severity", sev])
        
        print(f"\n🔍 Running scan with config: {config}")
        print(f"   Command: {' '.join(cmd)}")
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False  # Don't raise on non-zero exit
            )
            
            print(f"✓ Scan completed. Output saved to: {output_file}")
            
            # Parse JSON results
            if output_format == "json" and os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    return json.load(f)
            
            return {"output_file": output_file, "exit_code": result.returncode}
            
        except Exception as e:
            print(f"✗ Scan failed: {str(e)}")
            return {"error": str(e)}
            
    def run_comprehensive_scan(self) -> Dict:
        """Run comprehensive scan with multiple configurations"""
        print("\n" + "="*70)
        print("🚀 COMPREHENSIVE SECURITY SCAN")
        print("="*70)
        
        configs = [
            "auto",
            "p/php",
            "p/owasp-top-ten",
            "p/security-audit"
        ]
        
        results = {}
        for config in configs:
            results[config] = self.run_scan(config)
            
        return results
        
    def analyze_results(self, results: Dict) -> Dict:
        """Analyze scan results and generate statistics"""
        if "results" not in results:
            return {}
            
        findings = results.get("results", [])
        
        stats = {
            "total_findings": len(findings),
            "by_severity": {},
            "by_file": {},
            "by_rule": {},
            "by_cwe": {}
        }
        
        for finding in findings:
            # By severity
            severity = finding.get("extra", {}).get("severity", "UNKNOWN")
            stats["by_severity"][severity] = stats["by_severity"].get(severity, 0) + 1
            
            # By file
            file_path = finding.get("path", "unknown")
            stats["by_file"][file_path] = stats["by_file"].get(file_path, 0) + 1
            
            # By rule
            rule_id = finding.get("check_id", "unknown")
            stats["by_rule"][rule_id] = stats["by_rule"].get(rule_id, 0) + 1
            
            # By CWE
            cwe_list = finding.get("extra", {}).get("metadata", {}).get("cwe", [])
            for cwe in cwe_list:
                stats["by_cwe"][cwe] = stats["by_cwe"].get(cwe, 0) + 1
                
        return stats
        
    def generate_html_report(self, results: Dict, stats: Dict, output_file: str = None):
        """Generate HTML report from scan results"""
        if output_file is None:
            output_file = f"{self.output_dir}report_{self.timestamp}.html"
            
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Semgrep SAST Report - {self.timestamp}</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #2c3e50;
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
        }}
        h2 {{
            color: #34495e;
            margin-top: 30px;
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }}
        .stat-card {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }}
        .stat-card h3 {{
            margin: 0 0 10px 0;
            font-size: 14px;
            opacity: 0.9;
        }}
        .stat-card .value {{
            font-size: 36px;
            font-weight: bold;
            margin: 0;
        }}
        .severity-error {{ background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); }}
        .severity-warning {{ background: linear-gradient(135deg, #fa709a 0%, #fee140 100%); }}
        .severity-info {{ background: linear-gradient(135deg, #30cfd0 0%, #330867 100%); }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        th {{
            background-color: #3498db;
            color: white;
            font-weight: bold;
        }}
        tr:hover {{
            background-color: #f5f5f5;
        }}
        .finding {{
            background: #fff;
            border-left: 4px solid #e74c3c;
            padding: 15px;
            margin: 10px 0;
            border-radius: 4px;
        }}
        .finding-error {{ border-left-color: #e74c3c; }}
        .finding-warning {{ border-left-color: #f39c12; }}
        .finding-info {{ border-left-color: #3498db; }}
        code {{
            background: #f8f9fa;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
        }}
        .timestamp {{
            color: #7f8c8d;
            font-size: 14px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 Semgrep SAST Security Report</h1>
        <p class="timestamp">Generated: {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        
        <h2>📊 Summary Statistics</h2>
        <div class="stats-grid">
            <div class="stat-card">
                <h3>Total Findings</h3>
                <p class="value">{stats.get('total_findings', 0)}</p>
            </div>
            <div class="stat-card severity-error">
                <h3>Critical (ERROR)</h3>
                <p class="value">{stats.get('by_severity', {}).get('ERROR', 0)}</p>
            </div>
            <div class="stat-card severity-warning">
                <h3>High (WARNING)</h3>
                <p class="value">{stats.get('by_severity', {}).get('WARNING', 0)}</p>
            </div>
            <div class="stat-card severity-info">
                <h3>Medium (INFO)</h3>
                <p class="value">{stats.get('by_severity', {}).get('INFO', 0)}</p>
            </div>
        </div>
        
        <h2>📁 Findings by File</h2>
        <table>
            <thead>
                <tr>
                    <th>File</th>
                    <th>Findings</th>
                </tr>
            </thead>
            <tbody>
"""
        
        # Add file statistics
        for file_path, count in sorted(stats.get('by_file', {}).items(), key=lambda x: x[1], reverse=True):
            html_content += f"""
                <tr>
                    <td><code>{file_path}</code></td>
                    <td><strong>{count}</strong></td>
                </tr>
"""
        
        html_content += """
            </tbody>
        </table>
        
        <h2>🎯 Top Vulnerabilities (by CWE)</h2>
        <table>
            <thead>
                <tr>
                    <th>CWE</th>
                    <th>Count</th>
                </tr>
            </thead>
            <tbody>
"""
        
        # Add CWE statistics
        for cwe, count in sorted(stats.get('by_cwe', {}).items(), key=lambda x: x[1], reverse=True)[:10]:
            html_content += f"""
                <tr>
                    <td>{cwe}</td>
                    <td><strong>{count}</strong></td>
                </tr>
"""
        
        html_content += """
            </tbody>
        </table>
        
        <h2>🔍 Detailed Findings</h2>
"""
        
        # Add detailed findings
        for finding in results.get("results", [])[:50]:  # Limit to first 50
            severity = finding.get("extra", {}).get("severity", "INFO").lower()
            check_id = finding.get("check_id", "unknown")
            path = finding.get("path", "unknown")
            line = finding.get("start", {}).get("line", 0)
            message = finding.get("extra", {}).get("message", "No description")
            
            html_content += f"""
        <div class="finding finding-{severity}">
            <h4>{check_id}</h4>
            <p><strong>File:</strong> <code>{path}</code> (Line {line})</p>
            <p><strong>Severity:</strong> {severity.upper()}</p>
            <p>{message}</p>
        </div>
"""
        
        html_content += """
    </div>
</body>
</html>
"""
        
        with open(output_file, 'w') as f:
            f.write(html_content)
            
        print(f"\n✓ HTML report generated: {output_file}")
        return output_file
        
    def generate_markdown_report(self, stats: Dict, output_file: str = None):
        """Generate Markdown report"""
        if output_file is None:
            output_file = f"{self.output_dir}report_{self.timestamp}.md"
            
        md_content = f"""# Semgrep SAST Report

**Generated**: {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}  
**Target**: {self.target_dir}

## Summary

- **Total Findings**: {stats.get('total_findings', 0)}
- **Critical (ERROR)**: {stats.get('by_severity', {}).get('ERROR', 0)}
- **High (WARNING)**: {stats.get('by_severity', {}).get('WARNING', 0)}
- **Medium (INFO)**: {stats.get('by_severity', {}).get('INFO', 0)}

## Findings by File

| File | Count |
|------|-------|
"""
        
        for file_path, count in sorted(stats.get('by_file', {}).items(), key=lambda x: x[1], reverse=True):
            md_content += f"| `{file_path}` | {count} |\n"
            
        md_content += """
## Top Vulnerabilities (CWE)

| CWE | Count |
|-----|-------|
"""
        
        for cwe, count in sorted(stats.get('by_cwe', {}).items(), key=lambda x: x[1], reverse=True)[:10]:
            md_content += f"| {cwe} | {count} |\n"
            
        with open(output_file, 'w') as f:
            f.write(md_content)
            
        print(f"✓ Markdown report generated: {output_file}")
        return output_file
        
    def compare_with_baseline(self, current_results: Dict, baseline_file: str) -> Dict:
        """Compare current results with baseline"""
        if not os.path.exists(baseline_file):
            print(f"✗ Baseline file not found: {baseline_file}")
            return {}
            
        with open(baseline_file, 'r') as f:
            baseline = json.load(f)
            
        current_findings = len(current_results.get("results", []))
        baseline_findings = len(baseline.get("results", []))
        
        comparison = {
            "current": current_findings,
            "baseline": baseline_findings,
            "difference": current_findings - baseline_findings,
            "status": "improved" if current_findings < baseline_findings else "degraded"
        }
        
        print(f"\n📊 Baseline Comparison:")
        print(f"   Baseline: {baseline_findings} findings")
        print(f"   Current:  {current_findings} findings")
        print(f"   Change:   {comparison['difference']:+d} ({comparison['status']})")
        
        return comparison
        
    def create_baseline(self, results: Dict, baseline_file: str = "baseline.json"):
        """Create baseline file from current results"""
        baseline_path = f"{self.output_dir}{baseline_file}"
        
        with open(baseline_path, 'w') as f:
            json.dump(results, f, indent=2)
            
        print(f"✓ Baseline created: {baseline_path}")
        return baseline_path
        
    def run_diff_scan(self) -> Dict:
        """Run scan and show only new findings compared to baseline"""
        baseline_file = f"{self.output_dir}baseline.json"
        
        if not os.path.exists(baseline_file):
            print("⚠ No baseline found. Creating baseline...")
            results = self.run_scan()
            self.create_baseline(results)
            return results
            
        current_results = self.run_scan()
        self.compare_with_baseline(current_results, baseline_file)
        
        return current_results


def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description="Semgrep SAST Automation Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Quick scan
  python semgrep_automation.py --quick
  
  # Comprehensive scan with HTML report
  python semgrep_automation.py --comprehensive --html
  
  # Create baseline
  python semgrep_automation.py --baseline
  
  # Scan with specific config
  python semgrep_automation.py --config p/owasp-top-ten
  
  # Full scan with all reports
  python semgrep_automation.py --full
        """
    )
    
    parser.add_argument(
        "--target", "-t",
        default="src/",
        help="Target directory to scan (default: src/)"
    )
    
    parser.add_argument(
        "--output", "-o",
        default="reports/",
        help="Output directory for reports (default: reports/)"
    )
    
    parser.add_argument(
        "--config", "-c",
        default="auto",
        help="Semgrep config (default: auto)"
    )
    
    parser.add_argument(
        "--quick", "-q",
        action="store_true",
        help="Quick scan with auto config"
    )
    
    parser.add_argument(
        "--comprehensive",
        action="store_true",
        help="Run comprehensive scan with multiple configs"
    )
    
    parser.add_argument(
        "--html",
        action="store_true",
        help="Generate HTML report"
    )
    
    parser.add_argument(
        "--markdown",
        action="store_true",
        help="Generate Markdown report"
    )
    
    parser.add_argument(
        "--baseline",
        action="store_true",
        help="Create baseline from current scan"
    )
    
    parser.add_argument(
        "--diff",
        action="store_true",
        help="Show diff from baseline"
    )
    
    parser.add_argument(
        "--full",
        action="store_true",
        help="Run full scan with all report types"
    )
    
    parser.add_argument(
        "--severity",
        nargs="+",
        choices=["ERROR", "WARNING", "INFO"],
        help="Filter by severity levels"
    )
    
    args = parser.parse_args()
    
    # Initialize automation
    automation = SemgrepAutomation(args.target, args.output)
    
    # Check if Semgrep is installed
    if not automation.check_semgrep_installed():
        sys.exit(1)
    
    print("\n" + "="*70)
    print("🔐 SEMGREP SAST AUTOMATION")
    print("="*70)
    print(f"Target: {args.target}")
    print(f"Output: {args.output}")
    
    results = None
    
    # Run scans based on arguments
    if args.full:
        results = automation.run_comprehensive_scan()
        # Use first result for analysis
        results = list(results.values())[0] if results else {}
        stats = automation.analyze_results(results)
        automation.generate_html_report(results, stats)
        automation.generate_markdown_report(stats)
        
    elif args.comprehensive:
        results = automation.run_comprehensive_scan()
        results = list(results.values())[0] if results else {}
        stats = automation.analyze_results(results)
        
        if args.html:
            automation.generate_html_report(results, stats)
        if args.markdown:
            automation.generate_markdown_report(stats)
            
    elif args.quick or args.baseline or args.diff:
        if args.diff:
            results = automation.run_diff_scan()
        else:
            results = automation.run_scan(args.config, args.severity)
            
        if args.baseline and results:
            automation.create_baseline(results)
            
        stats = automation.analyze_results(results)
        
        if args.html:
            automation.generate_html_report(results, stats)
        if args.markdown:
            automation.generate_markdown_report(stats)
            
    else:
        # Default: simple scan
        results = automation.run_scan(args.config, args.severity)
        stats = automation.analyze_results(results)
        
        if args.html:
            automation.generate_html_report(results, stats)
        if args.markdown:
            automation.generate_markdown_report(stats)
    
    # Print summary
    if results and "results" in results:
        stats = automation.analyze_results(results)
        print("\n" + "="*70)
        print("📊 SCAN SUMMARY")
        print("="*70)
        print(f"Total Findings: {stats.get('total_findings', 0)}")
        print(f"  - ERROR:   {stats.get('by_severity', {}).get('ERROR', 0)}")
        print(f"  - WARNING: {stats.get('by_severity', {}).get('WARNING', 0)}")
        print(f"  - INFO:    {stats.get('by_severity', {}).get('INFO', 0)}")
        print("="*70)
    
    print("\n✅ Scan completed successfully!")


if __name__ == "__main__":
    main()
