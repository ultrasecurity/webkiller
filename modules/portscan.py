import sys
import requests
from colorama import Fore

def __start__():
    try:
        print(Fore.LIGHTBLACK_EX+"\n [!] Simple Port Scanner ! ! !")
        print(Fore.MAGENTA+"\n [!] Plase Enter IP/Domain\n")
        inp = input(Fore.RED+" ┌─["+Fore.LIGHTGREEN_EX+"WEBKILLER"+Fore.BLUE+"~"+Fore.WHITE+"@HOME"+Fore.RED+"/"+Fore.CYAN+"IG"+Fore.RED+"/"+Fore.LIGHTYELLOW_EX+"Port-Scan"+Fore.RED+"""]
 └──╼ """+Fore.WHITE+"卐 ")
        result = requests.get('https://api.hackertarget.com/nmap/?q=' + inp).text
        print(Fore.YELLOW+result)
        try:

            input(Fore.RED+" [!] "+Fore.GREEN+"Back To Menu (Press Enter...) ")
        except:
            print("")
            sys.exit()  
        
    except:
        print("\nExit :)")
