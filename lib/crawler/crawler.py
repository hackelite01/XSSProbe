import requests
from typing import List
from lib.helper.Log import *
from lib.helper.helper import *
from lib.core import *
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from multiprocessing import Process

class crawler:
	
	visited=[]
	
	@classmethod
	def getLinks(cls, base: str, proxy: dict = None, headers: dict = None, cookie: str = None) -> list:
		"""Extract links from target URL
		
		Args:
			base: Base URL to extract links from
			proxy: Proxy configuration
			headers: HTTP headers
			cookie: Cookie string
			
		Returns:
			List of discovered URLs
		"""
		lst=[]
	
		try:
			conn=session(proxy,headers,cookie)
			response=conn.get(base, timeout=10)
			response.raise_for_status()
			text=response.text
			isi=BeautifulSoup(text,"html.parser")
		except requests.exceptions.RequestException as e:
			Log.high(f"Failed to fetch {base}: {str(e)}")
			return []
		except Exception as e:
			Log.high(f"Error parsing {base}: {str(e)}")
			return []
			
		for obj in isi.find_all("a",href=True):
			url=obj["href"]
			
			if urljoin(base,url) in cls.visited:
				continue

			elif url.startswith("mailto:") or url.startswith("javascript:"):
				continue
	# :// will check if there any subdomain or any other domain but it will pass directory		
			elif url.startswith(base) or "://" not in url :
				lst.append(urljoin(base,url))
				cls.visited.append(urljoin(base,url))
			
		return lst

	@classmethod
	def crawl(cls, base: str, depth: int, proxy: dict = None, headers: dict = None, 
			 level: str = None, method: int = 2, cookie: str = None) -> None:
		"""Crawl website and test discovered URLs for XSS
		
		Args:
			base: Base URL to start crawling
			depth: Maximum crawling depth
			proxy: Proxy configuration
			headers: HTTP headers
			level: XSS payload level
			method: HTTP method to test
			cookie: Cookie string
		"""
		urls=cls.getLinks(base,proxy,headers,cookie)
		
		for url in urls:
			if url.startswith("https://") or url.startswith("http://"):
				try:
					p=Process(target=core.main, args=(url,proxy,headers,level,cookie,method))
					p.start()
					p.join()
				except Exception as e:
					Log.high(f"Process error for {url}: {str(e)}")
					continue
				if depth != 0:
					cls.crawl(url,depth-1,proxy,headers,level,method,cookie)
					
				else:
					break