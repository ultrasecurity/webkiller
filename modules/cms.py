import requests, builtwith
from colorama import Fore
import sys
def __start__():
    print(Fore.RED+" [!] Plase Enter Domain")
    target = input(Fore.RED+" ┌─["+Fore.LIGHTGREEN_EX+"WEBKILLER"+Fore.BLUE+"~"+Fore.WHITE+"@HOME"+Fore.RED+"/"+Fore.CYAN+"IG"+Fore.RED+"/"+Fore.LIGHTYELLOW_EX+"CMS-Detect"+Fore.RED+"""]
 └──╼ """+Fore.WHITE+"$ ")
    if not 'https://' in target or not 'http://' in target:
        target = 'http://'+target
    info = builtwith.parse(target)
    for name in info:
        value = ''
        for val in info[str(name)]:
            name = name.replace('-',' ')
            name = name.title()
            value += str(val) 
        print(Fore.BLUE+"\n"+name+': '+value)
    try:
        input(Fore.GREEN+" [*] Back To Menu (Press Enter...) ")
    except:
        print("")
        sys.exit()

