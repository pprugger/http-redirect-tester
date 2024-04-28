#!/usr/bin/python
import subprocess
import argparse
import os.path
from sys import platform

def run_check(domain, mode):
    responsecode = ""
    error = False
    outputstring = ""
    nexthop = ""
    arrow = " -> "
    redirects = 0
    redirecterror = False
    result = ""
    previoushop = ""
    domain = domain.rstrip()

    #check if mode is http or https
    if mode == "http":
        print("Output for: http://" + domain)
        outputstring += "http://"
        result = subprocess.run(["http", "--follow", "-h", "--all", domain], capture_output=True, text=True)
    elif mode == "https":
        print("Output for: https://" + domain)
        outputstring += "https://"
        result = subprocess.run(["https", "--follow", "-h", "--all", domain], capture_output=True, text=True)
    else:
        return

    #Parse the headers
    if result.returncode == 0:
        parser = result.stdout.split('\n')
        outputstring += domain + arrow

        for line in parser:
            if "HTTP/" in line:
                chunks = line.split(' ')
                responsecode =  int(chunks[1])
                if responsecode >= 200 and responsecode < 300:
                    outputstring += str(responsecode)
                    break
                if responsecode >= 300 and responsecode < 400:
                    redirects += 1
                if responsecode >= 400:
                    error = True
            if "location:" in line.lower():
                nexthop = line.split(' ')
                nexthop = nexthop[1].rstrip()
                outputstring += str(responsecode) + " " + nexthop + arrow
                if redirects == 1:
                    if "https://" in nexthop and mode == "http":
                        temp = nexthop.split('https://')               
                        if domain != temp[1].replace("/", ""):
                            redirecterror = True
                            error = True
                if "http://" in nexthop:
                    print_error("Unsecure redirect in chain.")
                    error = True          
    else:
        print_error("Seems the site does not exist.")
        outputstring = ""
        error = True
    
    print("Did " + str(redirects) + " redirects.")

    if error == True:
        print_error("Errors occured!")

    if redirecterror == True:
        print_error("First redirect is incorrect!")   
        
    if outputstring != "":
        if error == True or redirecterror == True:
            print_error(outputstring)
        else:
            print_success(outputstring)
    print_formatter()

def print_formatter():
    print("------------------------------------------------------")
    return

def print_error(msg):
    CRED = '\033[91m'
    CEND = '\033[0m'
    print(CRED + msg + CEND)

def print_success(msg):
    CGREEN  = '\33[32m'
    CEND = '\033[0m'
    print(CGREEN + msg + CEND)

def dns_check(domain):
    domain = domain.rstrip()
    result = subprocess.run(["nslookup", domain], capture_output=True, text=True)
    if result.returncode != 0:
        print_error("Domain " + domain + " not found!")
    return result.returncode

def ping_check(domain):
    domain = domain.rstrip()
    result = subprocess.run(["ping", "-c", "2", domain], capture_output=True, text=True)
    if result.returncode != 0:
        print_error("Could not ping " + domain + "!")
    return result.returncode
    
def is_tool(name):
    #check if tool is installed
    from shutil import which
    return which(name) is not None

def main():
    result = 0
    domain = ""
    
    #Platform check
    if platform != "linux" and platform != "linux2":
        print_error("This script currently only supports linux")
        return
        
    #Tool checks
    if not is_tool("httpie"):
        print("Please install httpie!")
        return
        
    if not is_tool("nslookup"):
        print("Please install nslookup!")
        return
    
    #Build arguments
    argparser = argparse.ArgumentParser(prog='http-redirect-tester.py')
    group = argparser.add_mutually_exclusive_group(required=True)
    group.add_argument("-i", "--input", help="the domain to check")
    group.add_argument("-l", "--list", help="a text file with a list of domains, one domain per line")
    argparser.add_argument("-m", "--mode", choices=["http","https"], required=True, help="Choose the operating mode")
    argparser.add_argument("-p", "--ping", action="store_true", default=False, help="Do a ping check of the domain")
    argparser.add_argument("-n", "--nslookup", action="store_true", default=False, help="Do a nslookup check of the domain")
    
    args = argparser.parse_args()
    domainlist = args.list
    mode = args.mode
    
    if mode != "http" and mode != "https":
        print_error("Unknown mode!")
        print_error("Exiting!")
        return
    
    #Run with single input domain
    if args.input:
        domain = args.input.rstrip()
        print_formatter()
        if args.nslookup:
            result += dns_check(domain)
        if args.ping:
            result += ping_check(domain)
        if result != 0:
            print_error("Errors for site " + domain + " occured!")
            return
        run_check(domain, mode)
    
    #run with input domain list
    if args.list:
        if not os.path.isfile(domainlist):
            print_error('File does not exist.')
            return
        
        f = open(domainlist, "r")
        lines = f.readlines()
        f.close()
        
        for line in lines:
            domain = line.rstrip()
            print_formatter()
            if args.nslookup:
                result += dns_check(domain)
            if args.ping:
                result += ping_check(domain)
            if result != 0:
                print_error("Errors for site " + domain + " occured!")
                continue
            run_check(domain, mode)

if __name__ == "__main__":
    main()