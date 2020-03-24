import requests
import sys
import time
from colorama import Fore
search = ['robots.txt',
'search/',
'admin/',
'login/',
'sitemap.xml',
'sitemap2.xml',
'config.php',
'wp-login.php',
'log.txt',
'update.php',
'INSTALL.pgsql.txt',
'user/login/',
'INSTALL.txt',
'profiles/',
'scripts/',
'LICENSE.txt',
'CHANGELOG.txt',
'themes/',
'inculdes/',
'misc/',
'user/logout/',
'user/register/',
'cron.php',
'filter/tips/',
'comment/reply/',
'xmlrpc.php',
'modules/',
'install.php',
'MAINTAINERS.txt',
'user/password/',
'node/add/',
'INSTALL.sqlite.txt',
'UPGRADE.txt',
'INSTALL.mysql.txt']

def __start__():
    try:
        print(Fore.RED+" [!] Plase Enter WebSite Address \n")
        url = input(Fore.RED+" ┌─["+Fore.LIGHTGREEN_EX+"WEBKILLER"+Fore.BLUE+"~"+Fore.WHITE+"@HOME"+Fore.RED+"/"+Fore.CYAN+"IG"+Fore.RED+"/"+Fore.LIGHTYELLOW_EX+"Robots_Scanner"+Fore.RED+"""]
 └──╼ """+Fore.WHITE+"卐 ")
        if 'http' in url:
            pass
        elif 'http' != url:
            url = ('http://'+url)
            
        for i in search:
            time.sleep(0.1)

            ur = (url+"/"+i)
            "http://pythons.ir/robots.txt"
            reqs = requests.get(ur)
            if reqs.status_code == 200 or reqs.status_code == 405:
                print(Fore.GREEN+" [+] "+ ur)
            else:
                print(Fore.RED+" [-] "+ur)
        try:
            input(Fore.RED+" [!] "+Fore.GREEN+"Back To Menu (Press Enter...) ")
        except:
            print("")
            sys.exit()  
    except:
        print("")