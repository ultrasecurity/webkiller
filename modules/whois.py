import sys
import requests
from colorama import Fore


def __start__():
        try:
                print(Fore.RED+"\n [!] Plase Enter IP/Domain\n")
                inp = input(Fore.RED+" ┌─["+Fore.LIGHTGREEN_EX+"WEBKILLER"+Fore.BLUE+"~"+Fore.WHITE+"@HOME"+Fore.RED+"/"+Fore.CYAN+"IG"+Fore.RED+"/"+Fore.LIGHTYELLOW_EX+"Whois"+Fore.RED+"""]
 └──╼ """+Fore.WHITE+"$ ")
                result = requests.get('http://api.hackertarget.com/whois/?q=' + inp).text
                
                print(Fore.BLUE+result)
                try:
                        input(Fore.RED+" [!] "+Fore.GREEN+"Back To Menu (Press Enter...) ")
                except:
                        print("")
                        sys.exit()  
        except:
                print("\nExit :)")