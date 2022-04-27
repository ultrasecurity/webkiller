import socket
import sys
import time
from colorama import Fore
def __start__():
    print(""" [!] Welcome To The Cloudflare Bypasser Part

 [!] Please Enter The Target Website Address\n""")
    subdom = ['ftp', 'cpanel', 'webmail', 'localhost', 'local', 'mysql', 'forum', 'driect-connect', 'blog', 'vb', 'forums', 'home', 'direct', 'forums', 'mail', 'access', 'admin', 'administrator', 'email', 'downloads', 'ssh', 'owa', 'bbs', 'webmin', 'paralel', 'parallels', 'www0', 'www', 'www1', 'www2', 'www3', 'www4', 'www5', 'shop', 'api', 'blogs', 'test', 'mx1', 'cdn', 'mysql', 'mail1', 'secure', 'server', 'ns1', 'ns2', 'smtp', 'vpn', 'm', 'mail2', 'postal', 'support', 'web', 'dev']

    site = input(Fore.RED+" ┌─["+Fore.LIGHTGREEN_EX+"WEBKILLER"+Fore.BLUE+"~"+Fore.WHITE+"@HOME"+Fore.RED+"/"+Fore.CYAN+"IG"+Fore.RED+"/"+Fore.LIGHTYELLOW_EX+"Bypass-CloudFlare"+Fore.RED+"""]
 └──╼ """+Fore.WHITE+"$ ")
    if site == "":
        try:
            print(Fore.RED+" [!] "+Fore.BLUE+"Please Enter Address :) \n")
            time.sleep(5)
            sys.exit()
        except:
            return
    for sub in subdom:
        try:
            hosts = str(sub) + "." + str(site)
            bypass = socket.gethostbyname(str(hosts))
            #print('Cloudflare Bypassed ! Real IP Address => '+bypass)
            print (" [!] CloudFlare Bypass " + str(bypass) + ' | ' + str(hosts))
        except Exception:
            pass
    try:
        input(Fore.GREEN+" [*] Back To Menu (Press Enter...) ")
    except:
        print("")
        sys.exit()