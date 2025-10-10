"""
HTML Report Generator for XSSProbe
Creates professional, interactive vulnerability reports
"""

import json
import os
from datetime import datetime
from typing import Dict, List, Optional
import base64


class HTMLReportGenerator:
    """Generate comprehensive HTML reports for XSS scan results"""
    
    def __init__(self, template_dir: str = "templates"):
        self.template_dir = template_dir
        self.report_data = {}
    
    def generate_report(self, scan_results: Dict, output_file: str = None) -> str:
        """Generate complete HTML report"""
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"xssprobe_report_{timestamp}.html"
        
        # Process scan results
        self.report_data = self._process_scan_results(scan_results)
        
        # Generate HTML content
        html_content = self._generate_html()
        
        # Save report
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return output_file
    
    def _process_scan_results(self, results: Dict) -> Dict:
        """Process and structure scan results for reporting"""
        processed = {
            "scan_info": {
                "target_url": results.get("target", "Unknown"),
                "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "scan_duration": results.get("duration", "Unknown"),
                "scanner_version": "XSSProbe v1.0",
                "total_requests": results.get("total_requests", 0),
                "total_forms": results.get("total_forms", 0)
            },
            "vulnerabilities": self._categorize_vulnerabilities(results.get("vulnerabilities", [])),
            "statistics": self._calculate_statistics(results.get("vulnerabilities", [])),
            "scan_coverage": results.get("coverage", {}),
            "recommendations": self._generate_recommendations(results.get("vulnerabilities", []))
        }
        return processed
    
    def _categorize_vulnerabilities(self, vulnerabilities: List[Dict]) -> Dict:
        """Categorize vulnerabilities by type and severity"""
        categories = {
            "reflected": {"high": [], "medium": [], "low": []},
            "dom": {"high": [], "medium": [], "low": []},
            "stored": {"high": [], "medium": [], "low": []},
            "other": {"high": [], "medium": [], "low": []}
        }
        
        for vuln in vulnerabilities:
            vuln_type = vuln.get("type", "other").lower()
            severity = vuln.get("severity", "medium").lower()
            
            if vuln_type not in categories:
                vuln_type = "other"
            if severity not in ["high", "medium", "low"]:
                severity = "medium"
            
            categories[vuln_type][severity].append(vuln)
        
        return categories
    
    def _calculate_statistics(self, vulnerabilities: List[Dict]) -> Dict:
        """Calculate vulnerability statistics"""
        stats = {
            "total": len(vulnerabilities),
            "by_severity": {"high": 0, "medium": 0, "low": 0},
            "by_type": {"reflected": 0, "dom": 0, "stored": 0, "other": 0},
            "risk_score": 0
        }
        
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "medium").lower()
            vuln_type = vuln.get("type", "other").lower()
            
            if severity in stats["by_severity"]:
                stats["by_severity"][severity] += 1
            
            if vuln_type in stats["by_type"]:
                stats["by_type"][vuln_type] += 1
        
        # Calculate risk score (weighted by severity)
        risk_weights = {"high": 10, "medium": 5, "low": 1}
        stats["risk_score"] = sum(
            stats["by_severity"][sev] * weight 
            for sev, weight in risk_weights.items()
        )
        
        return stats
    
    def _generate_recommendations(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """Generate security recommendations based on findings"""
        recommendations = []
        
        if any(v.get("type") == "reflected" for v in vulnerabilities):
            recommendations.append({
                "title": "Input Validation",
                "description": "Implement proper input validation and sanitization",
                "priority": "high",
                "details": [
                    "Validate all user inputs on server-side",
                    "Use whitelist validation where possible",
                    "Sanitize special characters before processing"
                ]
            })
        
        if any(v.get("type") == "dom" for v in vulnerabilities):
            recommendations.append({
                "title": "DOM Security",
                "description": "Secure client-side DOM manipulation",
                "priority": "high",
                "details": [
                    "Avoid using innerHTML with user data",
                    "Use textContent or innerText for text data",
                    "Implement Content Security Policy (CSP)"
                ]
            })
        
        if any(v.get("type") == "stored" for v in vulnerabilities):
            recommendations.append({
                "title": "Output Encoding",
                "description": "Implement proper output encoding",
                "priority": "critical",
                "details": [
                    "Encode all output based on context",
                    "Use appropriate encoding libraries",
                    "Implement defense in depth"
                ]
            })
        
        # General recommendations
        recommendations.append({
            "title": "Security Headers",
            "description": "Implement security headers",
            "priority": "medium",
            "details": [
                "Content-Security-Policy",
                "X-XSS-Protection",
                "X-Content-Type-Options",
                "X-Frame-Options"
            ]
        })
        
        return recommendations
    
    def _generate_html(self) -> str:
        """Generate complete HTML report"""
        return f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>XSSProbe Security Report</title>
    {self._get_css_styles()}
</head>
<body>
    <div class="container">
        {self._generate_header()}
        {self._generate_executive_summary()}
        {self._generate_vulnerability_details()}
        {self._generate_recommendations_section()}
        {self._generate_technical_details()}
        {self._generate_footer()}
    </div>
    {self._get_javascript()}
</body>
</html>
"""
    
    def _generate_header(self) -> str:
        """Generate report header"""
        scan_info = self.report_data["scan_info"]
        return f"""
        <header class="report-header">
            <div class="header-content">
                <h1>🔍 XSSProbe Security Report</h1>
                <div class="scan-info">
                    <div class="info-item">
                        <strong>Target:</strong> {scan_info['target_url']}
                    </div>
                    <div class="info-item">
                        <strong>Scan Date:</strong> {scan_info['scan_date']}
                    </div>
                    <div class="info-item">
                        <strong>Duration:</strong> {scan_info['scan_duration']}
                    </div>
                </div>
            </div>
        </header>
"""
    
    def _generate_executive_summary(self) -> str:
        """Generate executive summary section"""
        stats = self.report_data["statistics"]
        return f"""
        <section class="executive-summary">
            <h2>📊 Executive Summary</h2>
            <div class="summary-cards">
                <div class="summary-card critical">
                    <div class="card-number">{stats['by_severity']['high']}</div>
                    <div class="card-label">High Risk</div>
                </div>
                <div class="summary-card warning">
                    <div class="card-number">{stats['by_severity']['medium']}</div>
                    <div class="card-label">Medium Risk</div>
                </div>
                <div class="summary-card info">
                    <div class="card-number">{stats['by_severity']['low']}</div>
                    <div class="card-label">Low Risk</div>
                </div>
                <div class="summary-card total">
                    <div class="card-number">{stats['total']}</div>
                    <div class="card-label">Total Issues</div>
                </div>
            </div>
            <div class="risk-score">
                <h3>Overall Risk Score: <span class="score">{stats['risk_score']}</span></h3>
                <div class="risk-bar">
                    <div class="risk-fill" style="width: {min(stats['risk_score'] * 2, 100)}%"></div>
                </div>
            </div>
        </section>
"""
    
    def _generate_vulnerability_details(self) -> str:
        """Generate detailed vulnerability information"""
        vulns = self.report_data["vulnerabilities"]
        html = '<section class="vulnerability-details"><h2>🚨 Vulnerability Details</h2>'
        
        for vuln_type, severities in vulns.items():
            for severity, vuln_list in severities.items():
                if vuln_list:
                    html += f'<div class="vuln-category">'
                    html += f'<h3>{vuln_type.title()} XSS - {severity.title()} Severity</h3>'
                    
                    for vuln in vuln_list:
                        html += self._generate_vulnerability_card(vuln, severity)
                    
                    html += '</div>'
        
        html += '</section>'
        return html
    
    def _generate_vulnerability_card(self, vuln: Dict, severity: str) -> str:
        """Generate individual vulnerability card"""
        return f"""
        <div class="vuln-card {severity}">
            <div class="vuln-header">
                <h4>{vuln.get('url', 'Unknown URL')}</h4>
                <span class="severity-badge {severity}">{severity.upper()}</span>
            </div>
            <div class="vuln-details">
                <p><strong>Parameter:</strong> {vuln.get('parameter', 'N/A')}</p>
                <p><strong>Method:</strong> {vuln.get('method', 'N/A')}</p>
                <p><strong>Payload:</strong> <code>{vuln.get('payload', 'N/A')}</code></p>
                {self._generate_proof_of_concept(vuln)}
            </div>
        </div>
"""
    
    def _generate_proof_of_concept(self, vuln: Dict) -> str:
        """Generate proof of concept section"""
        if vuln.get('response'):
            return f"""
            <div class="poc-section">
                <h5>Proof of Concept:</h5>
                <pre><code>{vuln['response'][:500]}...</code></pre>
            </div>
"""
        return ""
    
    def _generate_recommendations_section(self) -> str:
        """Generate recommendations section"""
        recommendations = self.report_data["recommendations"]
        html = '<section class="recommendations"><h2>💡 Security Recommendations</h2>'
        
        for rec in recommendations:
            priority_class = rec['priority'].lower()
            html += f"""
            <div class="recommendation-card {priority_class}">
                <h3>{rec['title']}</h3>
                <p>{rec['description']}</p>
                <ul>
"""
            for detail in rec['details']:
                html += f'<li>{detail}</li>'
            
            html += '</ul></div>'
        
        html += '</section>'
        return html
    
    def _generate_technical_details(self) -> str:
        """Generate technical details section"""
        scan_info = self.report_data["scan_info"]
        return f"""
        <section class="technical-details">
            <h2>🔧 Technical Details</h2>
            <div class="tech-grid">
                <div class="tech-item">
                    <strong>Total Requests:</strong> {scan_info['total_requests']}
                </div>
                <div class="tech-item">
                    <strong>Forms Tested:</strong> {scan_info['total_forms']}
                </div>
                <div class="tech-item">
                    <strong>Scanner Version:</strong> {scan_info['scanner_version']}
                </div>
            </div>
        </section>
"""
    
    def _generate_footer(self) -> str:
        """Generate report footer"""
        return f"""
        <footer class="report-footer">
            <p>Generated by XSSProbe - Advanced XSS Vulnerability Scanner</p>
            <p>Report generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </footer>
"""
    
    def _get_css_styles(self) -> str:
        """Return CSS styles for the report"""
        return """
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #333; background: #f5f5f5; }
            .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
            
            .report-header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 10px; margin-bottom: 30px; }
            .header-content h1 { font-size: 2.5em; margin-bottom: 20px; }
            .scan-info { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; }
            .info-item { background: rgba(255,255,255,0.1); padding: 10px; border-radius: 5px; }
            
            .executive-summary { background: white; padding: 30px; border-radius: 10px; margin-bottom: 30px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            .summary-cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }
            .summary-card { text-align: center; padding: 25px; border-radius: 10px; color: white; }
            .summary-card.critical { background: #e74c3c; }
            .summary-card.warning { background: #f39c12; }
            .summary-card.info { background: #3498db; }
            .summary-card.total { background: #9b59b6; }
            .card-number { font-size: 3em; font-weight: bold; }
            .card-label { font-size: 1.1em; margin-top: 10px; }
            
            .risk-score { text-align: center; }
            .risk-bar { width: 100%; height: 20px; background: #ecf0f1; border-radius: 10px; overflow: hidden; margin-top: 10px; }
            .risk-fill { height: 100%; background: linear-gradient(90deg, #27ae60, #f39c12, #e74c3c); transition: width 0.3s ease; }
            .score { color: #e74c3c; font-weight: bold; }
            
            .vulnerability-details, .recommendations, .technical-details { background: white; padding: 30px; border-radius: 10px; margin-bottom: 30px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            .vuln-category { margin-bottom: 30px; }
            .vuln-card { border: 1px solid #ddd; border-radius: 8px; margin-bottom: 15px; overflow: hidden; }
            .vuln-card.high { border-left: 5px solid #e74c3c; }
            .vuln-card.medium { border-left: 5px solid #f39c12; }
            .vuln-card.low { border-left: 5px solid #3498db; }
            
            .vuln-header { background: #f8f9fa; padding: 15px; display: flex; justify-content: space-between; align-items: center; }
            .severity-badge { padding: 5px 10px; border-radius: 15px; color: white; font-size: 0.8em; font-weight: bold; }
            .severity-badge.high { background: #e74c3c; }
            .severity-badge.medium { background: #f39c12; }
            .severity-badge.low { background: #3498db; }
            
            .vuln-details { padding: 15px; }
            .poc-section { margin-top: 15px; padding: 15px; background: #f8f9fa; border-radius: 5px; }
            
            .recommendation-card { border: 1px solid #ddd; border-radius: 8px; padding: 20px; margin-bottom: 15px; }
            .recommendation-card.critical { border-left: 5px solid #e74c3c; }
            .recommendation-card.high { border-left: 5px solid #f39c12; }
            .recommendation-card.medium { border-left: 5px solid #3498db; }
            
            .tech-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; }
            .tech-item { padding: 15px; background: #f8f9fa; border-radius: 5px; }
            
            .report-footer { text-align: center; padding: 20px; color: #666; }
            
            h2 { color: #2c3e50; margin-bottom: 20px; padding-bottom: 10px; border-bottom: 2px solid #3498db; }
            h3 { color: #34495e; margin-bottom: 15px; }
            code { background: #f1f2f6; padding: 2px 5px; border-radius: 3px; font-family: 'Courier New', monospace; }
            pre { background: #f1f2f6; padding: 15px; border-radius: 5px; overflow-x: auto; }
            
            @media (max-width: 768px) {
                .container { padding: 10px; }
                .summary-cards { grid-template-columns: 1fr; }
                .vuln-header { flex-direction: column; align-items: flex-start; gap: 10px; }
            }
        </style>
"""
    
    def _get_javascript(self) -> str:
        """Return JavaScript for interactive features"""
        return """
        <script>
            // Add interactive features
            document.addEventListener('DOMContentLoaded', function() {
                // Smooth scrolling for anchor links
                document.querySelectorAll('a[href^="#"]').forEach(anchor => {
                    anchor.addEventListener('click', function (e) {
                        e.preventDefault();
                        document.querySelector(this.getAttribute('href')).scrollIntoView({
                            behavior: 'smooth'
                        });
                    });
                });
                
                // Collapsible vulnerability details
                document.querySelectorAll('.vuln-header').forEach(header => {
                    header.style.cursor = 'pointer';
                    header.addEventListener('click', function() {
                        const details = this.nextElementSibling;
                        details.style.display = details.style.display === 'none' ? 'block' : 'none';
                    });
                });
            });
        </script>
"""


# Example usage
if __name__ == "__main__":
    # Sample scan results
    sample_results = {
        "target": "https://example.com",
        "duration": "2 minutes 30 seconds",
        "total_requests": 127,
        "total_forms": 8,
        "vulnerabilities": [
            {
                "type": "reflected",
                "severity": "high",
                "url": "https://example.com/search",
                "parameter": "q",
                "method": "GET",
                "payload": "<script>alert('XSS')</script>",
                "response": "Found XSS in search parameter..."
            },
            {
                "type": "dom",
                "severity": "medium",
                "url": "https://example.com/page",
                "parameter": "fragment",
                "method": "GET",
                "payload": "#<img src=x onerror=alert(1)>",
                "response": "DOM manipulation detected..."
            }
        ]
    }
    
    # Generate report
    generator = HTMLReportGenerator()
    report_file = generator.generate_report(sample_results)
    print(f"Report generated: {report_file}")