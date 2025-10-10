
import argparse
import requests
import time
from lib.helper.helper import *
from lib.helper.Log import *
from lib.core import *
from lib.dom_xss import DOMXSSDetector
from lib.modes import *
from random import randint
from lib.crawler.crawler import *

epilog="""
Github: https://www.github.com/hackelite01/XSSProbe
"""
def generate_comprehensive_report(results, output_format="text"):
	"""Generate comprehensive report of all scan results"""
	total_vulns = sum(len(vuln_list) for vuln_list in results.values())
	
	if output_format == "json":
		import json
		report = {
			"scan_summary": {
				"total_vulnerabilities": total_vulns,
				"scan_types_completed": [k for k, v in results.items() if v],
				"timestamp": time.time()
			},
			"results": results
		}
		print(json.dumps(report, indent=2))
	
	elif output_format == "xml":
		print("<?xml version='1.0' encoding='UTF-8'?>")
		print("<xssprobe_report>")
		print(f"  <summary total_vulnerabilities='{total_vulns}'/>")
		for scan_type, vulns in results.items():
			if vulns:
				print(f"  <{scan_type} count='{len(vulns)}'/>")
		print("</xssprobe_report>")
	
	else:  # text format
		Log.info("="*60)
		Log.info("COMPREHENSIVE SCAN REPORT")
		Log.info("="*60)
		Log.info(f"Total vulnerabilities found: {total_vulns}")
		
		for scan_type, vulns in results.items():
			if vulns:
				Log.info(f"{scan_type.upper().replace('_', ' ')}: {len(vulns)} vulnerabilities")
		
		if total_vulns == 0:
			Log.info("No vulnerabilities found across all scan types.")
		
		Log.info("="*60)

def check(getopt):
	payload=int(getopt.payload_level)
	if payload > 6 and getopt.payload is None:
		Log.info("Do you want use custom payload (Y/n)?")
		answer=input("> "+W) 
		if answer.lower().strip() == "y":
			Log.info("Write the XSS payload below")
			payload=input("> "+W)
		else:
			payload=core.generate(randint(1,6))
	
	else:
		payload=core.generate(payload)
			
	return payload if getopt.payload is None else getopt.payload
	
def start():
	parse=argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter,usage="XSSProbe -u <target> [options]",epilog=epilog,add_help=False)
	
	pos_opt=parse.add_argument_group("Options")
	pos_opt.add_argument("--help",action="store_true",default=False,help="Show usage and help parameters")
	pos_opt.add_argument("-u",metavar="",help="Target url (e.g. http://testphp.vulnweb.com)")
	pos_opt.add_argument("--depth",metavar="",help="Depth web page to crawl. Default: 2",default=2)
	pos_opt.add_argument("--payload-level",metavar="",help="Level for payload Generator, 7 for custom payload. {1...6}. Default: 6",default=6)
	pos_opt.add_argument("--payload",metavar="",help="Load custom payload directly (e.g. <script>alert(2005)</script>)",default=None)
	pos_opt.add_argument("--method",metavar="",help="Method setting(s): \n\t0: GET\n\t1: POST\n\t2: GET and POST (default)",default=2,type=int)
	pos_opt.add_argument("--user-agent",metavar="",help="Request user agent (e.g. Chrome/2.1.1/...)",default=agent)
	pos_opt.add_argument("--single",metavar="",help="Single scan. No crawling just one address")
	pos_opt.add_argument("--proxy",default=None,metavar="",help="Set proxy (e.g. {'https':'https://10.10.1.10:1080'})")
	pos_opt.add_argument("--dom-xss",action="store_true",help="Enable DOM XSS detection (JavaScript analysis)")
	pos_opt.add_argument("--about",action="store_true",help="Print information about XSSProbe tool")
	pos_opt.add_argument("--cookie",help="Set cookie (e.g {'ID':'1094200543'})",default='''{"ID":"1094200543"}''',metavar="")
	
	# Advanced scanning modes
	adv_opt = parse.add_argument_group("Advanced Scanning Modes")
	adv_opt.add_argument("--stealth", action="store_true", help="Enable stealth scanning with evasion techniques")
	adv_opt.add_argument("--stealth-mode", choices=["quick", "normal", "thorough", "ultra_stealth"], 
	                     default="normal", help="Stealth scanning intensity level")
	adv_opt.add_argument("--authenticated", action="store_true", help="Enable authenticated area scanning")
	adv_opt.add_argument("--auth-type", choices=["basic", "bearer", "cookie", "api_key"], 
	                     help="Authentication type for authenticated scanning")
	adv_opt.add_argument("--username", metavar="", help="Username for basic authentication")
	adv_opt.add_argument("--password", metavar="", help="Password for basic authentication")
	adv_opt.add_argument("--token", metavar="", help="Bearer token or API key for authentication")
	adv_opt.add_argument("--auth-header", metavar="", default="Authorization", 
	                     help="Header name for token authentication")
	adv_opt.add_argument("--login-url", metavar="", help="Custom login URL for basic authentication")
	adv_opt.add_argument("--blind-xss", action="store_true", help="Enable blind XSS detection")
	adv_opt.add_argument("--callback-host", metavar="", help="External host for blind XSS callbacks")
	adv_opt.add_argument("--callback-port", type=int, default=8080, help="Port for blind XSS callback server")
	adv_opt.add_argument("--blind-wait", type=int, default=30, help="Time to wait for blind XSS callbacks (seconds)")
	adv_opt.add_argument("--api-scan", action="store_true", help="Enable API endpoint scanning")
	adv_opt.add_argument("--deep-dom", action="store_true", help="Enable deep DOM analysis with source/sink detection")
	adv_opt.add_argument("--custom-payloads", metavar="", help="File containing custom payloads (one per line)")
	adv_opt.add_argument("--output-format", choices=["text", "json", "xml"], default="text", 
	                     help="Output format for scan results")
	
	getopt=parse.parse_args()
	print(logo)
	Log.info("Starting XSSProbe...")
	
	# Load custom payloads if specified
	custom_payloads = None
	if getopt.custom_payloads:
		try:
			with open(getopt.custom_payloads, 'r') as f:
				custom_payloads = [line.strip() for line in f if line.strip()]
			Log.info(f"Loaded {len(custom_payloads)} custom payloads")
		except Exception as e:
			Log.info(f"Error loading custom payloads: {e}")
	
	# Initialize session for advanced scanners
	session = requests.Session()
	if getopt.proxy:
		session.proxies = eval(getopt.proxy)
	session.headers.update({'User-Agent': getopt.user_agent})
	
	# Initialize results storage
	all_results = {
		'basic_xss': [],
		'dom_xss': [],
		'stealth_xss': [],
		'authenticated_xss': [],
		'blind_xss': [],
		'api_xss': [],
		'deep_dom_xss': []
	}
	
	if getopt.u:
		# Basic XSS scanning
		Log.info("Starting basic XSS scanning...")
		core.main(getopt.u,getopt.proxy,getopt.user_agent,check(getopt),getopt.cookie,getopt.method)
		
		# Advanced scanning modes
		target_url = getopt.u
		payload = check(getopt)
		test_payloads = custom_payloads if custom_payloads else [payload]
		
		# Stealth scanning
		if getopt.stealth:
			Log.info("Starting stealth scanning with evasion techniques...")
			try:
				stealth_scanner = StealthScanner(session)
				stealth_results = stealth_scanner.scan_target(
					target_url, test_payloads, getopt.stealth_mode
				)
				all_results['stealth_xss'] = stealth_results
				
				if stealth_results:
					Log.high(f"Stealth scan found {len(stealth_results)} vulnerabilities!")
					for vuln in stealth_results:
						Log.high(f"Stealth XSS: {vuln['url']} - {vuln['parameter']}")
				else:
					Log.info("No stealth XSS vulnerabilities found.")
			except Exception as e:
				Log.info(f"Stealth scanning error: {e}")
		
		# Authenticated scanning
		if getopt.authenticated:
			Log.info("Starting authenticated area scanning...")
			try:
				auth_scanner = AuthenticatedScanner(session)
				
				# Handle different authentication types
				auth_success = False
				if getopt.auth_type == "basic" and getopt.username and getopt.password:
					auth_success = auth_scanner.authenticate_basic(
						getopt.username, getopt.password, getopt.login_url
					)
				elif getopt.auth_type == "bearer" and getopt.token:
					auth_success = auth_scanner.authenticate_bearer_token(
						getopt.token, getopt.auth_header
					)
				elif getopt.auth_type == "api_key" and getopt.token:
					auth_success = auth_scanner.authenticate_api_key(
						getopt.token, getopt.auth_header
					)
				elif getopt.auth_type == "cookie" and getopt.cookie:
					cookies = eval(getopt.cookie)
					auth_success = auth_scanner.authenticate_cookie(cookies)
				
				if auth_success or not getopt.auth_type:
					auth_results = auth_scanner.scan_authenticated_areas(
						target_url, test_payloads, depth=int(getopt.depth)
					)
					all_results['authenticated_xss'] = auth_results
					
					if auth_results:
						Log.high(f"Authenticated scan found {len(auth_results)} vulnerabilities!")
						for vuln in auth_results:
							Log.high(f"Authenticated XSS: {vuln['url']} - {vuln['parameter']}")
					else:
						Log.info("No authenticated XSS vulnerabilities found.")
				else:
					Log.info("Authentication failed - skipping authenticated scan")
			except Exception as e:
				Log.info(f"Authenticated scanning error: {e}")
		
		# Blind XSS scanning
		if getopt.blind_xss:
			Log.info("Starting blind XSS detection...")
			try:
				blind_config = {}
				if getopt.callback_host:
					blind_config["external_host"] = getopt.callback_host
				if getopt.callback_port:
					blind_config["callback_port"] = getopt.callback_port
				
				blind_scanner = BlindXSSScanner(session, blind_config)
				blind_results = blind_scanner.scan_for_blind_xss(
					target_url, wait_time=getopt.blind_wait
				)
				all_results['blind_xss'] = blind_results
				
				if blind_results:
					Log.high(f"Blind XSS scan found {len(blind_results)} vulnerabilities!")
					for vuln in blind_results:
						Log.high(f"Blind XSS: {vuln['url']} - {vuln['parameter']}")
				else:
					Log.info("No blind XSS vulnerabilities found.")
				
				# Clean up
				blind_scanner.stop_callback_server()
			except Exception as e:
				Log.info(f"Blind XSS scanning error: {e}")
		
		# API scanning
		if getopt.api_scan:
			Log.info("Starting API endpoint scanning...")
			try:
				api_scanner = APIScanner(session)
				endpoints = api_scanner.discover_api_endpoints(target_url)
				
				if endpoints:
					Log.info(f"Discovered {len(endpoints)} API endpoints")
					api_results = api_scanner.scan_api_endpoints(endpoints, test_payloads)
					all_results['api_xss'] = api_results
					
					if api_results:
						Log.high(f"API scan found {len(api_results)} vulnerabilities!")
						for vuln in api_results:
							Log.high(f"API XSS: {vuln['url']} - {vuln['parameter']} ({vuln['endpoint_type']})")
					else:
						Log.info("No API XSS vulnerabilities found.")
				else:
					Log.info("No API endpoints discovered.")
			except Exception as e:
				Log.info(f"API scanning error: {e}")
		
		# Deep DOM analysis
		if getopt.deep_dom:
			Log.info("Starting deep DOM analysis...")
			try:
				dom_scanner = DeepDOMScanner(session)
				dom_analysis = dom_scanner.analyze_dom_structure(target_url)
				dom_results = dom_scanner.test_dom_xss_payloads(target_url, test_payloads)
				all_results['deep_dom_xss'] = dom_results
				
				if dom_analysis:
					Log.info(f"DOM analysis found {len(dom_analysis.get('dom_sources', []))} sources "
					        f"and {len(dom_analysis.get('dom_sinks', []))} sinks")
				
				if dom_results:
					Log.high(f"Deep DOM scan found {len(dom_results)} vulnerabilities!")
					for vuln in dom_results:
						Log.high(f"Deep DOM XSS: {vuln['url']} - {vuln.get('source', 'unknown')}")
				else:
					Log.info("No deep DOM XSS vulnerabilities found.")
			except Exception as e:
				Log.info(f"Deep DOM scanning error: {e}")
		
		# Original DOM XSS detection
		if getopt.dom_xss:
			Log.info("Starting DOM XSS detection...")
			dom_detector = DOMXSSDetector()
			dom_vulnerabilities = dom_detector.scan_for_dom_xss(getopt.u)
			all_results['dom_xss'] = dom_vulnerabilities
			
			if dom_vulnerabilities:
				Log.info(f"Found {len(dom_vulnerabilities)} potential DOM XSS vulnerabilities!")
				for vuln in dom_vulnerabilities:
					Log.high(f"DOM XSS found: {vuln}")
			else:
				Log.info("No DOM XSS vulnerabilities detected.")
		
		# Crawling (if no single scan specified)
		if not getopt.single:
			Log.info("Starting crawler...")
			crawler.crawl(getopt.u,int(getopt.depth),getopt.proxy,getopt.user_agent,check(getopt),getopt.method,getopt.cookie)
		
		# Generate comprehensive report
		generate_comprehensive_report(all_results, getopt.output_format)
		
	elif getopt.single:
		# Single scan mode with advanced options
		Log.info("Starting single URL scan...")
		all_results = {
			'basic_xss': [],
			'dom_xss': [],
			'stealth_xss': [],
			'authenticated_xss': [],
			'blind_xss': [],
			'api_xss': [],
			'deep_dom_xss': []
		}
		
		# Initialize session
		session = requests.Session()
		if getopt.proxy:
			session.proxies = eval(getopt.proxy)
		session.headers.update({'User-Agent': getopt.user_agent})
		
		# Load custom payloads
		custom_payloads = None
		if getopt.custom_payloads:
			try:
				with open(getopt.custom_payloads, 'r') as f:
					custom_payloads = [line.strip() for line in f if line.strip()]
			except Exception as e:
				Log.info(f"Error loading custom payloads: {e}")
		
		# Basic single scan
		core.main(getopt.single,getopt.proxy,getopt.user_agent,check(getopt),getopt.cookie,getopt.method)
		
		target_url = getopt.single
		payload = check(getopt)
		test_payloads = custom_payloads if custom_payloads else [payload]
		
		# Apply advanced scanning modes to single URL
		if getopt.stealth:
			try:
				stealth_scanner = StealthScanner(session)
				stealth_results = stealth_scanner.scan_target(target_url, test_payloads, getopt.stealth_mode)
				all_results['stealth_xss'] = stealth_results
			except Exception as e:
				Log.info(f"Stealth scanning error: {e}")
		
		if getopt.authenticated:
			try:
				auth_scanner = AuthenticatedScanner(session)
				# Handle authentication as before
				auth_success = False
				if getopt.auth_type == "basic" and getopt.username and getopt.password:
					auth_success = auth_scanner.authenticate_basic(getopt.username, getopt.password, getopt.login_url)
				elif getopt.auth_type == "bearer" and getopt.token:
					auth_success = auth_scanner.authenticate_bearer_token(getopt.token, getopt.auth_header)
				elif getopt.auth_type == "api_key" and getopt.token:
					auth_success = auth_scanner.authenticate_api_key(getopt.token, getopt.auth_header)
				elif getopt.auth_type == "cookie" and getopt.cookie:
					cookies = eval(getopt.cookie)
					auth_success = auth_scanner.authenticate_cookie(cookies)
				
				if auth_success or not getopt.auth_type:
					auth_results = auth_scanner.scan_authenticated_areas(target_url, test_payloads, depth=1)
					all_results['authenticated_xss'] = auth_results
			except Exception as e:
				Log.info(f"Authenticated scanning error: {e}")
		
		if getopt.blind_xss:
			try:
				blind_config = {}
				if getopt.callback_host:
					blind_config["external_host"] = getopt.callback_host
				if getopt.callback_port:
					blind_config["callback_port"] = getopt.callback_port
				
				blind_scanner = BlindXSSScanner(session, blind_config)
				blind_results = blind_scanner.scan_for_blind_xss(target_url, wait_time=getopt.blind_wait)
				all_results['blind_xss'] = blind_results
				blind_scanner.stop_callback_server()
			except Exception as e:
				Log.info(f"Blind XSS scanning error: {e}")
		
		if getopt.api_scan:
			try:
				api_scanner = APIScanner(session)
				endpoints = api_scanner.discover_api_endpoints(target_url)
				if endpoints:
					api_results = api_scanner.scan_api_endpoints(endpoints, test_payloads)
					all_results['api_xss'] = api_results
			except Exception as e:
				Log.info(f"API scanning error: {e}")
		
		if getopt.deep_dom:
			try:
				dom_scanner = DeepDOMScanner(session)
				dom_analysis = dom_scanner.analyze_dom_structure(target_url)
				dom_results = dom_scanner.test_dom_xss_payloads(target_url, test_payloads)
				all_results['deep_dom_xss'] = dom_results
			except Exception as e:
				Log.info(f"Deep DOM scanning error: {e}")
		
		if getopt.dom_xss:
			dom_detector = DOMXSSDetector()
			dom_vulnerabilities = dom_detector.scan_for_dom_xss(getopt.single)
			all_results['dom_xss'] = dom_vulnerabilities
		
		# Generate report for single scan
		generate_comprehensive_report(all_results, getopt.output_format)
		
	elif getopt.about:
		print("""
***************
Project: XSSProbe - Advanced XSS Vulnerability Scanner
License: MIT
Author: Security Executions Code
Contributors: Hacktoberfest 2025 Community
Last updates: December 2024
Version: 2.0 with Advanced Scanning Modes

Features:
- Basic XSS Detection (Reflected, Stored)
- DOM XSS Analysis with JavaScript parsing
- Stealth Scanning with WAF evasion
- Authenticated Area Testing
- Blind XSS Detection with callback server
- API Endpoint Discovery and Testing
- Deep DOM Source/Sink Analysis
- Multiple output formats (text, JSON, XML)
- Custom payload support
- Comprehensive reporting

Advanced Scanning Modes:
🕵️  Stealth Mode: Evades WAF detection with rate limiting and encoding
🔐 Authenticated: Tests protected areas with session management
👻 Blind XSS: Detects time-delayed XSS with callback mechanisms
🔌 API Scanner: Discovers and tests REST/GraphQL/SOAP endpoints
🧠 Deep DOM: Advanced JavaScript source/sink flow analysis

Note: Use responsibly and only on authorized targets
****************
"""+epilog)
	elif getopt.help:
		parse.print_help()
		print("""
🚀 ADVANCED USAGE EXAMPLES:

Basic Scanning:
  python xssprobe.py -u https://example.com
  python xssprobe.py --single https://example.com/login

Stealth Scanning:
  python xssprobe.py -u https://example.com --stealth --stealth-mode thorough
  python xssprobe.py -u https://example.com --stealth --stealth-mode ultra_stealth

Authenticated Scanning:
  python xssprobe.py -u https://example.com --authenticated --auth-type basic --username admin --password secret
  python xssprobe.py -u https://example.com --authenticated --auth-type bearer --token your_jwt_token
  python xssprobe.py -u https://example.com --authenticated --auth-type cookie --cookie '{"session":"abc123"}'

Blind XSS Detection:
  python xssprobe.py -u https://example.com --blind-xss --callback-host your-domain.com --blind-wait 60

API Endpoint Testing:
  python xssprobe.py -u https://api.example.com --api-scan
  python xssprobe.py -u https://example.com --api-scan --stealth

Deep DOM Analysis:
  python xssprobe.py -u https://example.com --deep-dom --dom-xss

Comprehensive Scanning:
  python xssprobe.py -u https://example.com --stealth --authenticated --blind-xss --api-scan --deep-dom --auth-type basic --username user --password pass --callback-host yourdomain.com

Custom Payloads & Output:
  python xssprobe.py -u https://example.com --custom-payloads payloads.txt --output-format json
  python xssprobe.py -u https://example.com --stealth --output-format xml > report.xml

🔥 Pro Tips:
- Use --stealth for targets with WAF protection
- Combine --authenticated with --stealth for maximum coverage
- Set up --callback-host for blind XSS (requires public IP/domain)
- Use --api-scan on modern web applications
- Try --deep-dom for JavaScript-heavy sites
""")
	else:
		parse.print_help()
		
if __name__=="__main__":
	start()
 
