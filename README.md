<p align="center">   
A powerful XSS scanner made in python 3.7<br/>


## Installing 

Requirements: <br/>

<li> BeautifulSoup4 </li>

```bash
pip install bs4
```
<li> requests </li> 

```bash
pip install requests
```
<li> python 3.7 </li>
<br/>
Commands:

```bash
git clone https://github.com/hackelite01/XSSProbe
chmod 755 -R XSSProbe
cd XSSProbe
python3 xssprobe.py --help 
```
## Usage
Basic usage:

```bash
python3 xssprobe.py -u http://testphp.vulnweb.com
```
<br/>
Advanced usage:

```bash
python3 xssprobe.py --help
```

## Main features

* crawling all links on a website ( crawler engine )
* POST and GET forms are supported
* many settings that can be customized
* Advanced error handling
* Multiprocessing support.
* And many more..

## Note
* Currently it doesn't support DOM!

