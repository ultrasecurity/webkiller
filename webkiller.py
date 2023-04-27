#!/usr/bin/env python3  

"""This module first identifies, installs and launches the required libraries.
Then it runs the main program (WebKiller).
The "startup" script may not run correctly, due to the filtering of download sources (libraries),
    so make sure your VPN is connected."""


def setup():

    """The setup function checks the prerequisites for running the main program (WebKiller).
    The list of tasks that this script performs:
        - Determine the type of operating system
        - Check the Python version
        - Check internet connection
        - check PIP installation
        - check the installation of required libraries 
            - if not installed, it will be installed automatically
        - Diagnosing and reporting errors during the configuration process"""


    # ------------------- import libraries required by this script ------------------- #
    """to get os name, execute commands in os and set sleep time"""
    
    import platform, os, time


    # ---------------------------- set required variables ---------------------------- #
    """color variable to display the text in color,
    without any library - ANSI Escape Sequences"""
    
    # set color variables
    RED, GREEN, BLUE, YELLOW  = "\033[0;31m", "\033[0;32m", "\033[0;34m", "\033[0;33m"
    
    # bold variable to display the text in bold
    BOLD = '\033[1m'
    
    # reset variable to restart all of the effects
    RESET = "\033[0m"


    # ---------------------- check the operating system ------------------------------ #
    """check the operating system for compatibility and,
    set various variables"""
    
    # if target OS was Linux (e.g: ubuntu, android, etc)
    if platform.system().lower() == "linux":
        
        # 'clear' is a tool for clean terminal from text
        # this command is 'clear' in linux distro
        clear_screen = "clear"

        # identify null path to redirect extra texts to that place, it's /dev/null in linux
        # it causes the output texts from the execution of commands not to be displayed to the user
        null_path = "/dev/null"
        
        # use the 'ping' tool to check target internet connection
        # '-c' argument defines the number of ping
        # becuse the number of pings in Linux is continuous and non-stop
        ping = f"ping -c 3 google.com > {null_path}"

    # if target OS was Windows (e.g: Windows10, 11, etc)
    elif platform.system().lower() == "windows":
        
        # 'cls' is a tool for clean terminal from text
        # this command is 'cls' in windows distro
        clear_screen = "cls"

        # identify null path to redirect extra texts to that place, it's NUL in windows
        # it causes the output texts from the execution of commands not to be displayed to the user
        null_path = "NUL"
        
        # use the 'ping' tool to check target internet connection
        # We cannot use the '-c' argument to limit the number of pings,
            # because Windows will give us a permission error.
        ping = f"ping google.com > {null_path}"
    
    # if target os wasn't Linux or Windows
    else:
        
        # WebKiller only supports Linux and Windows operating systems.
        # Stop the program execution and informs the user
        exit(f"{BLUE}{BOLD}Webkiller{RESET} {RED}does not support your operating system, Please use {BOLD}Linux{RESET}{RED} or {BOLD}Windows{RESET}")
    
    # clean screen and target terminal
    os.system(clear_screen)


    # ------------------------ check the python version -------------------------------- #
    """check the user's Python version. if it was less that 3.8,
    the user will receive an incompatible version of Python error"""
    
    # notif to the user
    print (f"{YELLOW}[ ! ] {BLUE}Checking Python Version{RESET} .............. {YELLOW}WAITING{RESET}")
    
    # get user's python version (The version with which this program was run)
    python_version_major, python_version_minor = int(platform.python_version_tuple()[0]),  int(platform.python_version_tuple()[1])

    # check user's python version, if it was greater than or equal to 3.8
    if python_version_major >= 3 and python_version_minor >= 8:

        # notif to the user
        print (f"{YELLOW}[ ✔ ] {BLUE}Checking Python Version{RESET} .............. {GREEN}[ {python_version_major}.{python_version_minor} ]{RESET}")
    
    # if user's python version was less than 3.8
    else:

        # WebKiller requires Python 3.8 or higher
        # Stop the program execution and informs the user
        exit (f"""{YELLOW}[ X ] {BLUE}Checking Python Version{RESET} .............. {RED}[ {python_version_major}.{python_version_minor} ]{RESET}\n
{BOLD}WebKiller{RESET}{YELLOW} script requires {RED}{BOLD}Python version 3.8 or higher{RESET}{YELLOW} to work, Please make sure to install it manually{RESET}""")


    # ---------------------- check the internet connection ------------------------------ #
    """check the user's internet connection with the ping tool"""

    # notif to the user
    print (f"\n{YELLOW}[ ! ] {BLUE}Checking For Internet{RESET} .............. {YELLOW}WAITING{RESET}")

    # check user's internet connection (with ping tool - google)
    response = os.system(ping)

    # if response was 0, it means that the user's internet connection is established
    if response == 0:

        # notif to the user
        print (f"{YELLOW}[ ! ] {BLUE}Checking For Internet{RESET} .............. {GREEN}Connected{RESET}")

    # if response was not 0, it means that the user's internet connection is not established
    else:
        
        # WebKiller requires Internet to work
        # Stop the program execution and informs the user
        exit (f"""{YELLOW}[ X ] {BLUE}Checking For Internet{RESET} .............. {RED}Disconnected{RESET}\n
{BOLD}WebKiller{RESET}{YELLOW} script requires {RED}{BOLD}Internet{RESET}{YELLOW} to work, Please make sure your internet connection first{RESET}""")

    
    # ---------------------- check the pip installation ------------------------------ #
    """check if PIP is installed or not"""
    
    # if PIP import without problems, it means it is installed
    try:

        # check PIP tool is installed or not
        import pip

        # notif to the user
        print (f"{YELLOW}[ ✔ ] {BLUE}PIP{RESET} .............. {GREEN}[ Found ]{RESET}")
        
    # if PIP was not installed, it give us a ImportError error
    except ImportError:

        # WebKiller requires PIP tool to install its dependencies
        # Stop the program execution and informs the user
        exit (f"""{YELLOW}[ X ] {BLUE}PIP{RESET} .............. {RED}[ Not Found ]\n
{BOLD}WebKiller{RESET}{YELLOW} script requires {RED}{BOLD}PIP{RESET}{YELLOW} to install script prerequisites, Please make sure to install it{RESET}""")
    

    # ---------------------- installing prerequisite libraries ------------------------------ #
    """install the required modules"""

    # try to download, install and config required modules
    try:

        # notif to the user
        print (f"\n{YELLOW}[ ! ] {BLUE}Install prerequisites{RESET} .............. {YELLOW}[ WAITING ]{RESET}")

        # install that modules with PIP tool
        os.system(f"pip install -r requirements.txt > {null_path}")
    
    # if installation was unsuccessful
    except:
        
        # Webkiller requires to that modules to work
        # Stop the program execution and informs the user
        exit (f"""{YELLOW}[ X ] {BLUE}Install prerequisites{RESET} .............. {RED}[ FAILED ]\n
{BOLD}WebKiller{RESET}{YELLOW} script requires {RED}{BOLD}Install prerequisites{RESET}{YELLOW} to install script prerequisites,
There was a problem installing WebKiller prerequisites. Please re-install the 'requirements.txt' file libraries manually{RESET}""")


    # ---------------------- check the required modules ------------------------------ #
    """checking the correct installation of required modules"""

    # check the requests module to be install
    try:

        # check the installation with import module
        import requests

        # notif to the user
        print (f"{YELLOW}[ ✔ ] {BLUE}requests{RESET} .............. {GREEN}[ Found ]{RESET}")

    # if that module wasn't install, it give us a ImportError error
    except ImportError:

        # Webkiller requires to that modules to work
        # Stop the program execution and informs the user
        exit (f"""{YELLOW}[ X ] {BLUE}requests{RESET} .............. {RED}[ Not Found ]\n
{BOLD}WebKiller{RESET}{YELLOW} script requires {RED}{BOLD}requests{RESET}{YELLOW} module to work, Please make sure to install it manually{RESET}""")

    # check the colorama module to be install
    try:

        # check the installation with import module
        import colorama

        # notif to the user
        print (f"{YELLOW}[ ✔ ] {BLUE}colorama{RESET} .............. {GREEN}[ Found ]{RESET}")

    # if that module wasn't install, it give us a ImportError error
    except ImportError:

        # Webkiller requires to that modules to work
        # Stop the program execution and informs the user
        exit (f"""{YELLOW}[ X ] {BLUE}colorama{RESET} .............. {RED}[ Not Found ]\n
{BOLD}WebKiller{RESET}{YELLOW} script requires {RED}{BOLD}colorama{RESET}{YELLOW} module to work, Please make sure to install it manually{RESET}""")

    # check the ipapi module to be install
    try:

        # check the installation with import module
        import ipapi

        # notif to the user
        print (f"{YELLOW}[ ✔ ] {BLUE}ipapi{RESET} .............. {GREEN}[ Found ]{RESET}")

    # if that module wasn't install, it give us a ImportError error
    except ImportError:

        # Webkiller requires to that modules to work
        # Stop the program execution and informs the user
        exit (f"""{YELLOW}[ X ] {BLUE}ipapi{RESET} .............. {RED}[ Not Found ]\n
{BOLD}WebKiller{RESET}{YELLOW} script requires {RED}{BOLD}ipapi{RESET}{YELLOW} module to work, Please make sure to install it manually{RESET}""")

    # check the builtwith module to be install
    try:

        # check the installation with import module
        import builtwith

        # notif to the user
        print (f"{YELLOW}[ ✔ ] {BLUE}builtwith{RESET} .............. {GREEN}[ Found ]{RESET}")

    # if that module wasn't install, it give us a ImportError error
    except ImportError:

        # Webkiller requires to that modules to work
        # Stop the program execution and informs the user
        exit (f"""{YELLOW}[ X ] {BLUE}builtwith{RESET} .............. {RED}[ Not Found ]\n
{BOLD}WebKiller{RESET}{YELLOW} script requires {RED}{BOLD}builtwith{RESET}{YELLOW} module to work, Please make sure to install it manually{RESET}""")

    # notif to the user, installation and setup is done
    print (f"\n{YELLOW}[ ✔ ] {BLUE}Install prerequisites{RESET} .............. {GREEN}[ Done ]{RESET}")

    # asking the user to press Enter key (or any key) to continue, (this is becuse to see the result of setup)
    input(f"\n\n{YELLOW}[ + ] {BLUE}Script launch completed {GREEN}successfully{RESET}. {BLUE}Press {RED}Enter {BLUE}to start {BOLD}WebKiller{RESET}{BLUE} program{RESET}: ")
    
    # clear the screen and terminal (from text)
    os.system(clear_screen)


def start():
    import sys, requests, ipapi, builtwith, socket, os, time
    from colorama import Fore
    from helplist import helpp
    from modules import cms,Traceroute,reverseip,portscan,iplocation,httpheader,findsharedns,whois,dnslookup,robots,finder,cloudflare,wordpress


    #---------------------------
    while True:
        

        try:
            helpp.Banner()
            helpp.infolist1()
            number = input(Fore.RED+" ┌─["+Fore.LIGHTGREEN_EX+"WEBKILLER"+Fore.BLUE+"~"+Fore.WHITE+"@HOME"+Fore.RED+"""]
    └──╼ """+Fore.WHITE+"$ ").lower()
        except Exception as e:
            print("\n God Lock :) ", e)
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
    └──╼ """+Fore.WHITE+"$ ").lower()
        
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
    └──╼ """+Fore.WHITE+"$ ").lower()

            except:
                print("")
                sys.exit()
            if numcms == "1":
                helpp.infowp()
                try:
                    wp = input(Fore.RED+" ┌─["+Fore.LIGHTGREEN_EX+"WEBKILLER"+Fore.BLUE+"~"+Fore.WHITE+"@HOME"+Fore.RED+"/"+Fore.CYAN+"CMN"+Fore.RED+"/"+Fore.LIGHTYELLOW_EX+"WordPress"+Fore.RED+"""]
    └──╼ """+Fore.WHITE+"$ ").lower()
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


setup()
start()
