#!/usr/bin/python
# -*- coding: utf-8 -*- 

from modules import *
import modules.colors
import requests,json
import os
import socket
# import builtwith
from urllib2 import Request, urlopen, URLError, HTTPError

while True:

    os.system('clear')
    print(Banner)
    print '\r'



    def reverseHackTarget(website):
        website = addHTTP(website)
        webs = removeHTTP(website)
        url = "http://api.hackertarget.com/reverseiplookup/?q="
        combo = "{url}{website}".format(url=url, website=webs)
        request = requests.get(combo, headers=functions._headers, timeout=5).text.encode('UTF-8')
        if len(request) != 5:
            list = request.strip("").split("\n")
            for _links in list:
                if len(_links) != 0:
                    write(var="+", color=w, data=_links)
        else:
            write(var="@", color=r, data="Sorry, The webserver of the website you entered have no domains other then the one you gave :')")


    def reverseYouGetSignal(website):
        website = addHTTP(website)
        webs = removeHTTP(website)
        url = "https://domains.yougetsignal.com/domains.php"
        post = {
            'remoteAddress' : webs,
            'key' : ''
        }
        request = requests.post(url, headers=functions._headers, timeout=5, data=post).text.encode('UTF-8')

        grab = json.loads(request)

        Status = grab['status']
        IP = grab['remoteIpAddress']
        Domain = grab['remoteAddress']
        Total_Domains = grab['domainCount']
        Array = grab['domainArray']

        if (Status == 'Fail'):
            write(var="+", color=r, data="Sorry! Reverse Ip Limit Reached.")
        else:
            write(var="*", color=c, data="IP: " + IP + "")
            write(var="*", color=c, data="Domain: " + Domain + "")
            write(var="*", color=c, data="Total Domains: " + Total_Domains + "\n")

            domains = []

            for x, y in Array:
                domains.append(x)

            for res in domains:
                write(var="+", color=w, data=res)


    def geoip(website):
        website = addHTTP(website)
        webs = removeHTTP(website)
        url = "http://api.hackertarget.com/geoip/?q="
        combo = "{url}{website}".format(url=url, website=webs)
        request = requests.get(combo, headers=functions._headers, timeout=5).text.encode('UTF-8')
        if len(request) != 5:
            list = request.strip("").split("\n")
            for _links in list:
                if len(_links) != 0:
                    write(var="+", color=w, data=_links)
        else:
            write(var="@", color=r, data="Sorry, The webserver of the website you entered have no domains other then the one you gave :')")



    def httpheaders(website):
        website = addHTTP(website)
        webs = removeHTTP(website)
        url = "http://api.hackertarget.com/httpheaders/?q="
        combo = "{url}{website}".format(url=url, website=webs)
        request = requests.get(combo, headers=functions._headers, timeout=5).text.encode('UTF-8')
        if len(request) != 5:
            list = request.strip("").split("\n")
            for _links in list:
                if len(_links) != 0:
                    write(var="+", color=w, data=_links)
        else:
            write(var="@", color=r, data="Sorry, The webserver of the website you entered have no domains other then the one you gave :')")


    def cloudflare(website):
        subdomainlist = ["ftp", "cpanel", "webmail", "localhost", "local", "mysql", "forum", "driect-connect", "blog",
                         "vb", "forums", "home", "direct", "forums", "mail", "access", "admin", "administrator",
                         "email", "downloads", "ssh", "owa", "bbs", "webmin", "paralel", "parallels", "www0", "www",
                         "www1", "www2", "www3", "www4", "www5", "shop", "api", "blogs", "test", "mx1", "cdn", "mysql",
                         "mail1", "secure", "server", "ns1", "ns2", "smtp", "vpn", "m", "mail2", "postal", "support",
                         "web", "dev"]

        for sublist in subdomainlist:
            try:
                hosts = str(sublist) + "." + str(website)
                showip = socket.gethostbyname(str(hosts))
                print "[!] CloudFlare Bypass " + str(showip) + ' | ' + str(hosts)
            except:
                write(var="@", color=r,data="Sorry, The webserver of the website you entered have no domains other then the one you gave :')")


    def whois(website):
        website = addHTTP(website)
        webs = removeHTTP(website)
        url = "http://api.hackertarget.com/whois/?q="
        combo = "{url}{website}".format(url=url, website=webs)
        request = requests.get(combo, headers=functions._headers, timeout=5).text.encode('UTF-8')
        if len(request) != 5:
            list = request.strip("").split("\n")
            for _links in list:
                if len(_links) != 0:
                    write(var="+", color=w, data=_links)
        else:
            write(var="@", color=r, data="Sorry, The webserver of the website you entered have no domains other then the one you gave :')")


    def dnslookup(website):
        website = addHTTP(website)
        webs = removeHTTP(website)
        url = "http://api.hackertarget.com/dnslookup/?q="
        combo = "{url}{website}".format(url=url, website=webs)
        request = requests.get(combo, headers=functions._headers, timeout=5).text.encode('UTF-8')
        if len(request) != 5:
            list = request.strip("").split("\n")
            for _links in list:
                if len(_links) != 0:
                    write(var="+", color=w, data=_links)
        else:
            write(var="@", color=r, data="Sorry, The webserver of the website you entered have no domains other then the one you gave :')")


    def findshareddns(website):
        website = addHTTP(website)
        webs = removeHTTP(website)
        url = "http://api.hackertarget.com/findshareddns/?q="
        combo = "{url}{website}".format(url=url, website=webs)
        request = requests.get(combo, headers=functions._headers, timeout=5).text.encode('UTF-8')
        if len(request) != 5:
            list = request.strip("").split("\n")
            for _links in list:
                if len(_links) != 0:
                    write(var="+", color=w, data=_links)
        else:
            write(var="@", color=r, data="Sorry, The webserver of the website you entered have no domains other then the one you gave :')")


    def heading(heading, website, color, afterWebHead):
        space = " " * 10
        var = str(heading + " '" + website + "'" + str(afterWebHead))
        length = len(var) + 1; print "" # \n
        print("\n\n{color}" + var).format(color=color)
        print("{white}" + "-" * length + "--").format(white=w); print "" # \n


    def fetch(url, decoding='utf-8'):
        return urlopen(url).read().decode(decoding)


    def portchacker(domain):
        try:
            port = "http://api.hackertarget.com/nmap/?q=" + domain
            pport = fetch(port)
            print (pport)
        except:
            write(var="@", color=r, data="Sorry, The webserver of the website you entered have no domains other then the one you gave ")


    def CmsScan(website):

        try:
            website = addHTTP(website)
            webs = removeHTTP(website)
            w = builtwith.builtwith(website)

            print "[+] Cms : " , w["cms"][0]
            print "[+] Web Servers : " , w["web-servers"][0]
            print "[+] Programming Languages : " , w["programming-languages"][0]
            print "\n"
        except:
            write(var="@", color=r,data="Sorry, The webserver of the website you entered have no domains other then the one you gave ")


    def RobotTxt(domain):

        if not (domain.startswith('http://') or domain.startswith('https://')):
            domain = 'http://' + domain
        robot = domain + "/robots.txt"
        try:
            probot = fetch(robot)
            print(probot)
        except URLError:
            write(var="@", color=r, data="Sorry, The webserver of the website you entered have no domains other then the one you gave ")


    def PageAdminFinder(link):
        f = open("admin.txt","r")
        print "\n\nAvilable Links : \n"
        while True:
            sub_link = f.readline()
            if not sub_link:
                break
            req_link = "http://" + link + "/" + sub_link
            req = Request(req_link)
            try:
                response = urlopen(req)
            except HTTPError as e:
                continue
            except URLError as e:
                break
                write(var="@", color=r, data="Sorry, The webserver of the website you entered have no domains other then the one you gave ")
            else:
                print "Find Page >> ", req_link


    def Traceroute(website):
        try:
            port = "https://api.hackertarget.com/mtr/?q=" + website
            pport = fetch(port)
            print (pport)
        except:
            write(var="@", color=r, data="Sorry, The webserver of the website you entered have no domains other then the one you gave ")


    def HoneypotDetector(ipaddress):
        honey = "https://api.shodan.io/labs/honeyscore/" + ipaddress + "?key=C23OXE0bVMrul2YeqcL7zxb6jZ4pj2by"

        try:
            phoney = fetch(honey)

        except URLError:
            phoney = None
            write(var="@", color=r, data="Sorry, The webserver of the website you entered have no domains other then the one you gave ")

        if phoney:
            print('Honeypot Percent : {probability}'.format(
                color='2' if float(phoney) < 0.5 else '3', probability=float(phoney) * 10))
            print "\n"



    def ping(website):
        try:
            port = "http://api.hackertarget.com/nping/?q=" + website
            pport = fetch(port)
            print (pport)
        except:
            write(var="@", color=r, data="Sorry, The webserver of the website you entered have no domains other then the one you gave ")


    print b + """

    1 - Reverse IP With HackTarget
    2 - Reverse IP With YouGetSignal
    3 - Geo IP Lookup
    4 - Whois
    5 - Bypass CloudFlare
    6 - DNS Lookup
    7 - Find Shared DNS
    8 - Show HTTP Header
    9 - Port Scan
    10 - CMS Scan
    11 - Page Admin Finder
    12 - Robots.txt
    13 - Traceroute
    14 - Honeypot Detector
    15 - Ping
    16 - All
    17 - Exit
    
    """

    EnterApp = raw_input("Enter : ")



    if EnterApp == "1":
        m = raw_input("Enter Address Website = ")
        heading(heading="Reversing IP With HackTarget", color=c, website=m, afterWebHead="")
        reverseHackTarget(m)
        print "\n"
        raw_input("[*] Back To Menu (Press Enter...) ")


    elif EnterApp == "2":
        m = raw_input("Enter Address Website = ")
        heading(heading="Reverse IP With YouGetSignal", color=c, website=m, afterWebHead="")
        reverseYouGetSignal(m)
        print "\n"
        raw_input("[*] Back To Menu (Press Enter...) ")


    elif EnterApp == "3":
        m = raw_input("Enter Address Website = ")
        heading(heading="Geo IP Lookup", color=c, website=m, afterWebHead="")
        geoip(m)
        print "\n"
        raw_input("[*] Back To Menu (Press Enter...) ")


    elif EnterApp == "4":
        m = raw_input("Enter Address Website = ")
        heading(heading="Whois", color=c, website=m, afterWebHead="")
        whois(m)
        print "\n"
        raw_input("[*] Back To Menu (Press Enter...) ")


    elif EnterApp == "5":
        m = raw_input("Enter Address Website = ")
        heading(heading="Bypass Cloudflare", color=c, website=m, afterWebHead="")
        cloudflare(m)
        print "\n"
        raw_input("[*] Back To Menu (Press Enter...) ")


    elif EnterApp == "6":
        m = raw_input("Enter Address Website = ")
        heading(heading="DNS Lookup", color=c, website=m, afterWebHead="")
        dnslookup(m)
        print "\n"
        raw_input("[*] Back To Menu (Press Enter...) ")


    elif EnterApp == "7":
        m = raw_input("Enter Address Website = ")
        heading(heading="Find Shared DNS", color=c, website=m, afterWebHead="")
        findshareddns(m)
        print "\n"
        raw_input("[*] Back To Menu (Press Enter...) ")


    elif EnterApp == "8":
        m = raw_input("Enter Address Website = ")
        heading(heading="Show HTTP Header", color=c, website=m, afterWebHead="")
        httpheaders(m)
        print "\n"
        raw_input("[*] Back To Menu (Press Enter...) ")


    elif EnterApp == "9":
        m = raw_input("Enter Address Website = ")
        heading(heading="PortChacker", color=c, website=m, afterWebHead="")
        portchacker(m)
        print "\n"
        raw_input("[*] Back To Menu (Press Enter...) ")



    elif EnterApp == "10":
        m = raw_input("Enter Address Website = ")
        heading(heading="CMS Scan", color=c, website=m, afterWebHead="")
        CmsScan(m)
        print "\n"
        raw_input("[*] Back To Menu (Press Enter...) ")



    elif EnterApp == "11":
        m = raw_input("Enter Address Website = ")
        heading(heading="Page Admin Finder", color=c, website=m, afterWebHead="")
        PageAdminFinder(m)
        print "\n"
        raw_input("[*] Back To Menu (Press Enter...) ")


        

    elif EnterApp == "12":
        m = raw_input("Enter Address Website = ")
        heading(heading="Robot.txt", color=c, website=m, afterWebHead="")
        RobotTxt(m)
        raw_input("[*] Back To Menu (Press Enter...) ")



    elif EnterApp == "13":
        m = raw_input("Enter Address Website = ")
        heading(heading="Traceroute", color=c , website=m , afterWebHead="")
        Traceroute(m)
        print "\n"
        raw_input("[*] Back To Menu (Press Enter...) ")


    elif EnterApp == "14":
        m = raw_input("Enter (IP) Address = ")
        heading(heading="Honeypot Detector", color=c , website=m , afterWebHead="")
        HoneypotDetector(m)
        print "\n"
        raw_input("[*] Back To Menu (Press Enter...) ")



    elif EnterApp == "15":
        m = raw_input("Enter Address Website = ")
        heading(heading="Ping", color=c , website=m , afterWebHead="")
        ping(m)
        print "\n"
        raw_input("[*] Back To Menu (Press Enter...) ")


    elif EnterApp == "16":

        m = raw_input("Enter Address Website = ")

        heading(heading="Reversing IP With HackTarget", color=c, website=m, afterWebHead="")
        reverseHackTarget(m)

        heading(heading="Reverse IP With YouGetSignal", color=c, website=m, afterWebHead="")
        reverseYouGetSignal(m)

        heading(heading="Geo IP Lookup", color=c, website=m, afterWebHead="")
        geoip(m)

        heading(heading="Whois", color=c, website=m, afterWebHead="")
        whois(m)

        heading(heading="Bypass Cloudflare", color=c, website=m, afterWebHead="")
        cloudflare(m)

        heading(heading="DNS Lookup", color=c, website=m, afterWebHead="")
        dnslookup(m)

        heading(heading="Find Shared DNS", color=c, website=m, afterWebHead="")
        findshareddns(m)

        heading(heading="Show HTTP Header", color=c, website=m, afterWebHead="")
        httpheaders(m)

        heading(heading="Port Scan", color=c, website=m, afterWebHead="")
        portchacker(m)

        heading(heading="Cms Scan", color=c, website=m, afterWebHead="")
        CmsScan(m)

        heading(heading="Robot.txt", color=c, website=m, afterWebHead="")
        RobotTxt(m)

        heading(heading="Traceroute", color=c , website=m , afterWebHead="")
        Traceroute(m)

        heading(heading="Ping", color=c , website=m , afterWebHead="")
        ping(m)

        heading(heading="Page Admin Finder", color=c, website=m, afterWebHead="")
        PageAdminFinder(m)
        
        print "\n"
        raw_input("[*] Back To Menu (Press Enter...) ")


    elif EnterApp == "17":
        print "\n"
        break


    else:
        print "[!] Please Enter a Number"
        raw_input("[*] Back To Menu (Press Enter...) ")
