# -*- coding: utf-8 -*- 

from modules.colors import *
import requests
import re

_headers = {
    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.11 (KHTML, like Gecko) Chrome/23.0.1271.64 Safari/537.11',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Encoding': 'gzip,deflate,sdch',
    'Accept-Language': 'en-US,en;q=0.8',
    'Connection': 'keep-alive'
}

empty_Website = "\n\t{red}[+] Please Enter A Website :/\n\t\t".format(red=r, cyan=c)

wrong_URL = "\n\t{red}[-] Please Enter a Valid And Correct URL (i.e, google.com)\n\t\t".format(red=r)

str_Index = "\n\t{red}[-] Please Input a Integer (i.e, 1, 2, 3) :\\\n\t\t".format(red=r)

val_Select = "\t{}[-] Please Use The Index Value From The List\n\t\t[+] Not By Your Own :/\n\t\t\t \n".format(r)

def webNotEmpty(website):

    if len(website) >= 1:
        return "valid"
    else:
        return "!valid"

def validWebsite(website):

    web = webNotEmpty(website)
    if web is "valid":
        if not (re.match(r"(^(http://|https://)?([a-z0-9][a-z0-9-]*\.)+[a-z0-9][a-z0-9-]*$)", website)):
            exit(wrong_URL)
    else:
        exit(empty_Website)

def cleanURL(website):

    web = validWebsite(website)
    website = website.replace("http://", "")
    website = website.replace("http://www.", "")
    website = website.replace("https://", "")
    website = website.replace("https://www.", "")
    website = website.replace("www.", ""); return(website)

def removeHTTP(website):

    website = cleanURL(website); return(website)

def addHTTP(website):

    website = cleanURL(website)
    website = ("http://" + website); return(website)

def write(var, color, data):
    if var == None:
        print(color + str(data))
    elif var != None:
        print("{white}[{cyan}" + var + "{white}] " + color + str(data)).format(
        	white=w, cyan=c
    	)

def Request(website, _timeout=None, _encode=None):

    try:
        if _encode == None:
            return requests.get(website, headers=_headers, timeout=_timeout).content
        elif _encode == True:
            return requests.get(website, headers=_headers, timeout=_timeout).text.encode('utf-8')
    except requests.exceptions.MissingSchema:
        pass
    except requests.exceptions.ContentDecodingError:
        pass
    except requests.exceptions.ConnectionError:
        return fg + sb + "\n[-] Error: Sorry! You Enter A Wrong Website Or Website Is Off"
        pass
    except Exception as e:
        return fc + sb + "[-] Error: " + fg + sb + str(e)
        pass