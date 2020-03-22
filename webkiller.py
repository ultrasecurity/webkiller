#!/usr/bin/env python3  
import sys
import socket
import os
import time
from helplist import helpp
from modules import cms,Traceroute,reverseip,portscan,iplocation,httpheader,findsharedns,whois,dnslookup,robots,finder,cloudflare,wordpress



try:
    from colorama import Fore
except:
    os.system("clear")
    print(Fore.RED+"""\n Please Install colorama\n
    pip3 install colorama
        """)

#---------------------------

try:
    import requests
except:
    os.system("clear")
    print(Fore.RED+"""\n Please Install requests\n
    pip3 install requests
        """)

#---------------------------


try:
    import ipapi
except:
    os.system("clear")
    print(Fore.RED+"""\n Please Install ipapi\n
    pip3 install ipapi
        """)

#---------------------------


try:
    import builtwith
except:
    os.system("clear")
    print(Fore.RED+"""\n Please Install builtwith\n
    pip3 install builtwith
        """)

#---------------------------
while True:
    

    try:
        helpp.Banner()
        helpp.infolist1()
        number = input(Fore.RED+" ┌─["+Fore.LIGHTGREEN_EX+"WEBKILLER"+Fore.BLUE+"~"+Fore.WHITE+"@HOME"+Fore.RED+"""]
 └──╼ """+Fore.WHITE+"卐 ").lower()
    except:
        print("\n God Lock :) ")
        sys.exit()
    if number == '4':

        print
        sys.exit()
            
        #####################
        #####################

    elif number == "3":
        helpp.infolist3()

        #####################

    elif number == "":
        print(Fore.RED+" [!]"+Fore.BLUE+" Please Enter Number :))))")
        input("")

#----------------------------------------------------------------------------------

#Information Gathering

    elif number == '1':
        try:
            helpp.Banner()
            helpp.infolist2()
            infor = input(Fore.RED+" ┌─["+Fore.LIGHTGREEN_EX+"WEBKILLER"+Fore.BLUE+"~"+Fore.WHITE+"@HOME"+Fore.RED+"/"+Fore.CYAN+"Information Gathering"+Fore.RED+"""]
 └──╼ """+Fore.WHITE+"卐 ").lower()
    
            if infor == "1":
                helpp.Banner()
                cloudflare.__start__()

                #####################

            elif infor == "2":
                helpp.Banner()
                cms.__start__()

                #####################


            elif infor == "3":
                helpp.Banner()
                Traceroute.__start__()

                #####################


            elif infor == "4":
                helpp.Banner()
                reverseip.__start__()

                #####################

            elif infor == "5":
                helpp.Banner()
                portscan.__start__()

                #####################
            
            elif infor == "6":
                helpp.Banner()
                iplocation.__start__()

                #####################

            elif infor == "7":
                helpp.Banner()
                httpheader.__start__()

                #####################

            elif infor == "8":
                helpp.Banner()
                findsharedns.__start__()

                #####################

            elif infor == "9":
                helpp.Banner()
                whois.__start__()    

                #####################

            elif infor == "10":
                helpp.Banner()
                dnslookup.__start__()  
                #####################

            elif infor == "11":
                helpp.Banner()
                robots.__start__()
                #####################

            elif infor == "12":
                helpp.Banner()
                finder.__start__()

                #####################

            elif infor == "13":
                input(Fore.RED+" [!]"+Fore.GREEN+" Back To Menu (Press Enter...) ")

                #####################
            elif infor == "14":
                sys.exit()
                
                #####################
            elif infor == "":
                input(Fore.RED+" [!]"+Fore.GREEN+" Please Enter Number (Press Enter...) ")
        except KeyboardInterrupt:
            print("")
            sys.exit()

#------------------------------------------------------------------------------------------------
    elif number == "2":
        helpp.infolist4()
        try:
            numcms = input(Fore.RED+" ┌─["+Fore.LIGHTGREEN_EX+"WEBKILLER"+Fore.BLUE+"~"+Fore.WHITE+"@HOME"+Fore.RED+"/"+Fore.CYAN+"CMS Detection"+Fore.RED+"""]
 └──╼ """+Fore.WHITE+"卐 ").lower()

        except:
            print("")
            sys.exit()
        if numcms == "1":
            helpp.infowp()
            try:
                wp = input(Fore.RED+" ┌─["+Fore.LIGHTGREEN_EX+"WEBKILLER"+Fore.BLUE+"~"+Fore.WHITE+"@HOME"+Fore.RED+"/"+Fore.CYAN+"CMN"+Fore.RED+"/"+Fore.LIGHTYELLOW_EX+"WordPress"+Fore.RED+"""]
 └──╼ """+Fore.WHITE+"卐 ").lower()
            except:
                print("")
                sys.exit()
            if wp == "1":
                helpp.Banner()
                wordpress.wpplug()
            elif wp == "2":
                helpp.Banner()
                wordpress.user()
            elif wp == "3":
                try:
                    input(Fore.GREEN+" [*] Back To Menu (Press Enter...) ")
                except:
                    print("\n")
                    sys.exit()
        elif numcms == "2":
            helpp.Banner()
            print(Fore.RED+" [!]"+Fore.BLUE+" Coming Soon ! ")
            try:
                input(Fore.GREEN+" [*] Back To Menu (Press Enter...) ")
            except:
                print("")
                sys.exit()
        elif numcms == "3":
            helpp.Banner()
            print(Fore.RED+" [!]"+Fore.BLUE+" Coming Soon ! ")
            try:
                input(Fore.GREEN+" [*] Back To Menu (Press Enter...) ")
            except:
                print("")
                sys.exit()
        
        elif numcms == "4":
            try:
                input(Fore.GREEN+" [*] Back To Menu (Press Enter...) ")
            except:
                print("")
                sys.exit()
        elif numcms == "" or False:
            try:
                input(Fore.GREEN+" [*] Back To Menu (Press Enter...) ")
            except:
                print("")
                sys.exit()





