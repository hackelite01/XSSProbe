
from lib.helper.helper import * 
from datetime import datetime
class Log:

	@classmethod
	def info(cls, text: str) -> None:
		"""Log info level message"""
		print("["+Y+datetime.now().strftime("%H:%M:%S")+N+"] ["+G+"INFO"+N+"] "+text)
 
	@classmethod
	def warning(cls, text: str) -> None:
		"""Log warning level message"""
		print("["+Y+datetime.now().strftime("%H:%M:%S")+N+"] ["+Y+"WARNING"+N+"] "+text)

	@classmethod
	def high(cls, text: str) -> None:
		"""Log critical/high severity message"""
		print("["+Y+datetime.now().strftime("%H:%M:%S")+N+"] ["+R+"CRITICAL"+N+"] "+text)
 		