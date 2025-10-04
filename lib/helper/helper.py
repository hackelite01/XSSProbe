
import requests
import json
from typing import Optional
##### Warna ####### 
N = '\033[0m'
W = '\033[1;37m' 
B = '\033[1;34m' 
M = '\033[1;35m' 
R = '\033[1;31m' 
G = '\033[1;32m' 
Y = '\033[1;33m' 
C = '\033[1;36m' 
##### Styling ######
underline = "\033[4m"
##### Default ######
agent = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36'} 
line="—————————————————" 
#####################
def session(proxies: dict = None, headers: dict = None, cookie: str = None) -> requests.Session:
	"""Create configured requests session
	
	Args:
		proxies: Proxy configuration dictionary
		headers: HTTP headers dictionary
		cookie: Cookie string in JSON format
		
	Returns:
		Configured requests Session object
	"""
	r = requests.Session()
	if proxies:
		r.proxies = proxies
	if headers:
		r.headers = headers
	if cookie:
		try:
			r.cookies.update(json.loads(cookie))
		except json.JSONDecodeError:
			print(f"Warning: Invalid cookie format: {cookie}")
	return r

logo = G + """
██╗  ██╗███████╗███████╗██████╗ ██████╗  ██████╗ ██████╗ ███████╗
╚██╗██╔╝██╔════╝██╔════╝██╔══██╗██╔══██╗██╔═══██╗██╔══██╗██╔════╝
 ╚███╔╝ ███████╗███████╗██████╔╝██████╔╝██║   ██║██████╔╝█████╗  
 ██╔██╗ ╚════██║╚════██║██╔═══╝ ██╔══██╗██║   ██║██╔══██╗██╔══╝  
██╔╝ ██╗███████║███████║██║     ██║  ██║╚██████╔╝██████╔╝███████╗
╚═╝  ╚═╝╚══════╝╚══════╝╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝
                                                                 
""" + R + "{v1.0}" + G + underline + C + "https://github.com/hackelite01/XSSProbe" + N
