#!/usr/bin/env python3
########################################################################
# This header measures out 72 Characters of line length
# File Name : scanio.py
# Author : Gabriel Akonom
# Creation Date : 24Sep2020
# Last Modified : Sun Oct 18 21:47:15 2020
# Description: scans a network using /dev/tcp or netcat
#              with several productivity features
#
########################################################################

from multiprocessing import Process, set_start_method, Pool, Value, Lock
from xml.etree import ElementTree as ET
from xml.dom import minidom
from datetime import datetime
from itertools import repeat
import subprocess as sub
from subprocess import STDOUT, check_output
from re import search
import pyyed
import time
import socket
import threading
import argparse
import sys
import os

class Timer(object):

    def __init__(self, interval=1):

        self.interval = interval

        thread = threading.Thread(target=self.run, args=())
        thread.daemon = True                            # Daemonize thread
        thread.start()                                  # Start the execution

    def run(self):
        global secs
        """ Method that runs forever """
        tic = time.perf_counter()
        while True:
            # Do something
            toc = time.perf_counter()
            secs = f'{toc - tic:0.1f}'
            time.sleep(self.interval)

class update_progress(object):

    def __init__(self, interval=0.25):

        self.interval = interval

        thread = threading.Thread(target=self.run, args=())
        thread.daemon = True                            # Daemonize thread
        thread.start()                                  # Start the execution

    def run(self):
        global currcount
        global totalscans
        global secs
        global progtext
        pps = 0
        while currcount.value < totalscans:
            progress = currcount.value / totalscans
            if float(secs) > 0:
                pps = currcount.value / float(secs)
                pps = "{:.0f}".format(pps)
            mon, sec = divmod(float(secs), 60)
            mon = "{:.0f}".format(mon)
            sec = "{:.0f}".format(sec)
            barLength = 10 # Modify this to change the length of the progress bar
            status = ""
            if isinstance(progress, int):
                progress = float(progress)
            if not isinstance(progress, float):
                progress = 0
                status = "error: progress var must be float\r\n"
            if progress < 0:
                progress = 0
                status = "Halt...                                                          \r\n"
            if progress >= 1:
                progress = 1
                status = "Done...                                                           \r\n"
            block = int(round(barLength*progress))
            smallProgress = "{:.1f}".format(progress*100)
            progtext = "\rPercent: [{0}] {1}% {2} {3}/{4}. {5}m {6}s spent. ~{7} ports/s     ".format( "#"*block + "-"*(barLength-block), smallProgress, status, currcount.value, totalscans, mon, sec, pps)
            sys.stdout.write(progtext)
            sys.stdout.flush()
            time.sleep(0.05)

def indent(elem, level=0):
    i = "\n" + level*"  "
    if len(elem):
        if not elem.text or not elem.text.strip():
            elem.text = i + "  "
        if not elem.tail or not elem.tail.strip():
            elem.tail = i
        for elem in elem:
            indent(elem, level+1)
        if not elem.tail or not elem.tail.strip():
            elem.tail = i
    else:
        if level and (not elem.tail or not elem.tail.strip()):
            elem.tail = i

#http://thoughtsbyclayg.blogspot.com/2008/10/parsing-list-of-numbers-in-python.html
def parseRange(nputstr=""):
    selection = set()
    invalid = set()
    # tokens are comma seperated values
    tokens = [x.strip() for x in nputstr.split(',')]
    for i in tokens:
        try:
            # typically tokens are plain old integers
            selection.add(int(i))
        except:
            # if not, then it might be a range
            try:
                token = [int(k.strip()) for k in i.split('-')]
                if len(token) > 1:
                    token.sort()
                    # we have items seperated by a dash
                    # try to build a valid range
                    first = token[0]
                    last = token[len(token)-1]
                    for x in range(first, last+1):
                        selection.add(x)
            except:
                # not an int and not a range...
                invalid.add(i)
    # Report invalid tokens before returning valid selection
    if len(invalid) != 0:
        print("Invalid set: " + str(invalid))
    return selection

def get_ip_address(net):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect((net + '.1', 30100))
    return s.getsockname()[0]

def addSubnet(addy):
    with lock:
        pivot = get_ip_address(addy)
        tree = ET.parse('scanio.xml')
        root = tree.getroot()
        newSN = ET.SubElement(root, 'subnet')
        newaddy = ET.SubElement(newSN, 'subnet-address')
        newaddy.text = addy
        newpivot = ET.SubElement(newSN, 'pivot')
        newpivot.text = pivot
        newname = ET.SubElement(newSN, 'subnet-name')
        newname.text = ""
        indent(root)
        tree.write("scanio.xml")
    return

def addHost(addy):
    with lock:
        sl = addy.split('.')
        subnetstr = './subnet/[subnet-address = "{0}.{1}.{2}"]'.format(sl[0], sl[1], sl[2])
        # pivotstr = './subnet/[subnet-address = "{0}.{1}.{2}"]/pivot'.format(sl[0], sl[1], sl[2])
        tree = ET.parse('scanio.xml')
        root = tree.getroot()
        subnet = root.find(subnetstr)
        # pivot = root.find(pivotstr).text
        # if addy != pivot:
        newip = ET.SubElement(subnet, 'host')
        newaddr = ET.SubElement(newip, 'address')
        newaddr.text = addy
        newhn = ET.SubElement(newip, 'hostname')
        newhn.text = ''
        newun = ET.SubElement(newip, 'username')
        newun.text = ''
        newpw = ET.SubElement(newip, 'password')
        newpw.text = ''
        indent(root)
        tree.write("scanio.xml")
    return

def addPort(addy, num, banner, robust):
    with lock:
        addyStr = './subnet/host/[address = "'+str(addy)+'"]'
        tree = ET.parse('scanio.xml')
        root = tree.getroot()
        host = root.find(addyStr)
        rbl = robust.splitlines()
        if len(rbl) > 5:
            robust = '\n'.join(rbl[5:-3])
        else:
            robust = None
        if search('ssh', banner):
            # print('SSH PORT FOUND!!')
            portnum = host.find('./port/[number="'+str(num)+'"]')
            if portnum == None:
                newport = ET.SubElement(host, 'port')
                newportnum = ET.SubElement(newport, 'number')
                newportnum.text = str(num)
                newportbanner = ET.SubElement(newport, 'banner')
                newportbanner.text = banner
                newportrobust = ET.SubElement(newport, 'robust')
                newportrobust.text = robust
                newtunnel = ET.SubElement(newport, 'tunnel')
                newtunnellport = ET.SubElement(newtunnel, 'local-port')
                newtunnellport.text = ""
                newtunneltarget = ET.SubElement(newtunnel, 'tunnel-target')
                newtunneltarget.text = ""
                newtunneltport = ET.SubElement(newtunnel, 'tunnel-target-port')
                newtunneltport.text = ""
                newtunnelbuild = ET.SubElement(newtunnel, 'existing-tunnel-port')
                newtunnelbuild.text = ""
                indent(root)
                tree.write("scanio.xml")
            else:
                bannertext = portnum.find('banner')
                if bannertext.text != banner:
                    bannertext.text = banner
                indent(root)
                tree.write("scanio.xml")
        else:
            portnum = host.find('./port/[number="'+str(num)+'"]')
            if portnum == None:
                newport = ET.SubElement(host, 'port')
                newportnum = ET.SubElement(newport, 'number')
                newportnum.text = str(num)
                newportbanner = ET.SubElement(newport, 'banner')
                newportbanner.text = banner
                newportrobust = ET.SubElement(newport, 'robust')
                newportrobust.text = robust
                indent(root)
                tree.write("scanio.xml")
            else:
                bannertext = portnum.find('banner')
                if bannertext.text != banner:
                    bannertext.text = banner
                indent(root)
                tree.write("scanio.xml")
    return

def bannerGrab(addy, port):
    try:
        tcp_args = 'timeout 1 bash -c "exec 2<>/dev/tcp/'+str(addy)+'/'+str(port)+';echo EOF>&2; cat<&2"'
        tcp_res = sub.Popen(tcp_args, stdout = sub.PIPE, stderr = sub.PIPE, universal_newlines = True, shell = True)
        tcp_res.wait()
        out, err = tcp_res.communicate()
        tcp_res.kill()
    except:
        out = 'BannerError.'

    if search('concurrent connection', out):
        out = ''

    return out.partition('\n')[0]

def robustScan(addy, port):
    try:
        tcp_args = 'timeout 60 bash -c "nmap -T4 -A -sT -Pn ' + str(addy) + ' -p ' + str(port) + '"'
        tcp_res = sub.Popen(tcp_args, stdout = sub.PIPE, stderr = sub.PIPE, universal_newlines = True, shell = True)
        tcp_res.wait()
        out, err = tcp_res.communicate()
        tcp_res.kill()
    except:
        out = 'NMAP-Error.'

    if search('concurrent connection', out):
        out = ''

    return out


#### start port scan on linux using netcat
def callScanNC(addy, tp):
    #netcat SCAN BEGIN
    # print('Original Input: {0}'.format(addy))
    oi = addy.split(':')
    # print(oi)
    addy = oi[0]
    robustTF = bool(oi[1])
    # print('Address: {0}   Robust: {1}'.format(addy, str(robustTF)))
    try:
        tcp_args = ['timeout 0.5 /bin/bash -c "nc -nvzw1 '+str(addy)+' '+str(tp)+' 2>&1"']
        tcp_res = sub.Popen(tcp_args, stdout = sub.PIPE, stderr = sub.PIPE, universal_newlines = True, shell = True)
        tcp_res.wait()
        result, err = tcp_res.communicate()
        tcp_res.kill()
        # tcp_args = ['nc -nvzw1 '+str(addy)+' '+str(tp)+' 2>&1']
        # result = check_output(['nc -nvzw1 '+str(addy)+' '+str(tp)+' 2>&1'], stderr=STDOUT, timeout=0.3)
    except:
        result = 'Encountered and error while scanning {0}'.format(addy)
        print(result, end='\r')
        return result

    if "open" in result or "succ" in result:
        if robustTF:
            robust = robustScan(addy, tp)
        else:
            robust = None
        addyStr = './subnet/host/[address = "'+str(addy)+'"]'
        #Banner Grab
        banner = bannerGrab(addy, tp)
        tree = ET.parse('scanio.xml')
        root = tree.getroot()
        hoste = root.find(addyStr)
        if hoste == None:
            addHost(addy)
            addPort(addy, tp, banner, robust)
        else:
            addPort(addy, tp, banner, robust)
    with currcount.get_lock():
        currcount.value += 1
    return result

#### start port scan on linux using /dev/tcp
def callScanP(addy, tp):
    global currcount
    #/dev/tcp SCAN BEGIN
    # print('Original Input: {0}'.format(addy))
    oi = addy.split(':')
    # print(oi)
    addy = oi[0]
    robustTF = bool(oi[1])
    # print('Address: {0}   Robust: {1}'.format(addy, str(robustTF)))
    try:
        tcp_args = ['timeout 1 /bin/bash -c "exec echo > /dev/tcp/'+str(addy)+'/'+str(tp)+'";retval=$?;echo $retval']
        tcp_res = sub.Popen(tcp_args, stdout = sub.PIPE, stderr = sub.PIPE, universal_newlines = True, shell = True)
        tcp_res.wait()
        result, err = tcp_res.communicate()
        tcp_res.kill()
    except:
        result = 'Encountered and error while scanning {0}'.format(addy)
    if result == '0\n':
        if robustTF:
            robust = robustScan(addy, tp)
        else:
            robust = None
        addyStr = './subnet/host/[address = "'+str(addy)+'"]'
        #Banner Grab
        banner = bannerGrab(addy, tp)
        tree = ET.parse('scanio.xml')
        root = tree.getroot()
        hoste = root.find(addyStr)
        if hoste == None:
            addHost(addy)
            addPort(addy, tp, banner, robust)
        else:
            addPort(addy, tp, banner, robust)
        return 'Success!!'
    with currcount.get_lock():
        currcount.value += 1
    return result

#### start port scan on windows
def callScanW(addy, tp):
    #Python Socket Scan Begin
    try:
        s = socket.socket(socket.AF_INET,socket.SOCK_STREAM, 0)
        result = s.connect_ex((addy,tp))
        ans = s.recv(200)
        s.close()  
        if result == 0:
            addyStr = './subnet/host/[address = "'+str(addy)+'"]'
            #Banner Grab
            banner = ans.decode('utf-8')
            tree = ET.parse('scanio.xml')
            root = tree.getroot()
            hoste = root.find(addyStr)
            if hoste == None:
                addHost(addy)
                addPort(addy, tp, banner)
            else:
                addPort(addy, tp, banner)
    except:
        result = 'Scan failed on socket {0}:{1}'.format(addy, tp)
    with currcount.get_lock():
        currcount.value += 1
    return 1

## prepare for port scans
def initiate():
    #Get Options
    uinput = argparse.ArgumentParser()
    uinput.add_argument("address", help = "REQUIRED: This address will be a 3-octet or a 4-octet address.'")
    uinput.add_argument("-s", "--start", help = "Starting host number. The scan will begin at this host number.  Defaults to 1")
    uinput.add_argument("-e", "--end", help = "Ending host number. The scan will stop at this number if included Defaults to 254 \
                                               ***If this option is enabled, you cannot use -r or --range.***")
    uinput.add_argument("-r", "--range", help = "The range of hosts. This can be a comma separated list or a range ie: 1-30. \
                                                This can also be a CIDR. ie: /27 - for 30 hosts.  If a CIDR is used, the number \
                                                of hosts will be added to the start.\
                                                /30 = 2 hosts   /29 = 6 hosts \
                                                /28 = 14 hosts  /27 = 30 hosts /26 = 62 hosts  /25 = 126 hosts \
                                                 /24 = 254 hosts \
                                                ***If this option is enabled, you cannot use -e or --end.***")
    uinput.add_argument("-p", "--ports", help = "The ports to be scanned. Should be comma-separated or can be a range ie: 1-30.\
                                                Defaults to list from: https://rb.gy/x86g6c")
    uinput.add_argument("-c", "--clearlog", help = "Clears the log and starts fresh.", action="store_true")
    uinput.add_argument("-f", "--fast", help = "Performs a fast scan using netcat vs the default /dev/tcp.  This option does have \
                                                the potential to miss some ports.  REQUIRES NETCAT to be installed. \
                                                ", action="store_true")
    uinput.add_argument("--show", help = "Shows the currently logged results for the address.  When used with --map \
                                            this will recreate the network map also", action="store_true")
    uinput.add_argument("-m", "--map", help = "Creates a network map to a .graphml file \
                                                Download yEd to edit scanio.graphml from https://www.yworks.com/products/yed", action="store_true")
    uinput.add_argument("-rb", "--robust", help = "Runs NMAP -A on found ports. WARNING: THIS WILL DRASTICALLY SLOW \
                                                DOWN THE SCAN. ***REQUIRES NMAP TO BE INSTALLED***", action="store_true")                                                

    ipstart = 1
    ipend = 254
    fulladd = False
    clearlog = False
    netmap = False
    robust = False

    opts = uinput.parse_args()

    net = opts.address
    if opts.show:
        printall(net)
        if opts.map:
            netgraph()
        sys.exit()

    if len(net.split('.')) > 3:
        fulladd = True
        ipstart = int(net.split('.')[3])
        ipend = int(net.split('.')[3])
        net = '.'.join(net.split('.')[0:3])
    
    if opts.start and len(net.split('.')) < 3:
        ipstart = int(opts.start)
     
    if opts.end and len(net.split('.')) < 3:
        ipend = int(opts.end)
        if opts.range != None:
            print('You entered a full address, and/or provided an end/start host, and/or provided a range (or a combination thereof)')
            sys.exit(2)

    if opts.range:
        iprange = opts.range
        if opts.end != None and len(net.split('.')) <= 3:
            print('You entered a full address, and/or provided an end/start host, and/or provided a range (or a combination thereof)')
            sys.exit(2)
        if "/30" in iprange:
            ipend=ipstart+2
            final_range = set()
            for p in range(ipstart,ipend):
                final_range.add(p)
        elif "/29" in iprange:
            ipend=ipstart+6
            final_range = set()
            for p in range(ipstart,ipend):
                final_range.add(p)
        elif "/28" in iprange:
            ipend=ipstart+14
            final_range = set()
            for p in range(ipstart,ipend):
                final_range.add(p)
        elif "/27" in iprange:
            ipend=ipstart+30
            final_range = set()
            for p in range(ipstart,ipend):
                final_range.add(p)
        elif "/26" in iprange:
            ipend=ipstart+62
            final_range = set()
            for iport in range(ipstart,ipend):
                final_range.add(iport)
        elif "/25" in iprange:
            ipend=ipstart+126
            final_range = set()
            for p in range(ipstart,ipend):
                final_range.add(p)
        elif "/24" in iprange:
            ipend=ipstart+254
            final_range = set()
            for p in range(ipstart,ipend+1):
                final_range.add(p)
        else:
            final_range = parseRange(iprange)
    else:
        final_range = set()
        for p in range(ipstart,ipend+1):
            final_range.add(p)

    if opts.ports:
        uports = opts.ports
        pports = uports
    else:
        uports = "20-25,50-53,67-69,80,110,119,123,135-139,143,161,162,389,443,989,990,3389,2222,4444,8080"
        pports = 'from https://rb.gy/x86g6c (plus some custom): \n|    {0}'.format(uports)
    final_ports = parseRange(uports)

    hostnum = len(final_range)
    if hostnum <= 1:
        phostvar = 'Scanning host {0}.{1}'.format(net, str(min(final_range)))
    elif hostnum > 1:
        phostvar = 'Scanning hosts {0}.{1} to {0}.{2}'.format(net, str(min(final_range)), str(max(final_range)))
    totalscans = hostnum*len(final_ports)
    
    if opts.fast:
        operation = callScanNC
        totaltime = totalscans / 18
    elif os.name == 'nt':
        operation = callScanW
    else:
        operation = callScanP
        totaltime = totalscans / 12

    mon, sec = divmod(float(totaltime), 60)
    mon = "{:.0f}".format(mon)
    sec = "{:.0f}".format(sec)

    print('| {0} Total Scans. Approximately {1}m {2}s'.format(totalscans, mon, sec))
    print('|--> {0}'.format(phostvar))
    print('|--> Scanning ports {0}'.format(pports))        
        
    tree = ET.parse('scanio.xml')
    root = tree.getroot()
    subnetstr = './subnet/[subnet-address = "'+net+'"]'
    subnet = root.find(subnetstr)
    if subnet == None:
        addSubnet(net)
    
    if opts.fast:
        operation = callScanNC
    elif os.name == 'nt':
        operation = callScanW
    else:
        operation = callScanP

    if fulladd == True:
        printnet = '{0}.{1}'.format(net, min(final_range))
    else:
        printnet = net

    if opts.map:
        print('|--> Will create a network map to scanio.graphml in current directory...')
        print('|    Download yEd to edit scanio.graphml from https://www.yworks.com/products/yed')
        netmap = True
    
    if opts.clearlog:
        print('|--> The current log will be cleared and recreated')
        clearlog = True
                
    if opts.robust:
        print('|--> Will perform NMAP Robust scan on found ports')
        robust = True

    return operation, net, final_range, final_ports, totalscans, printnet, clearlog, netmap, robust

def netgraph():
    print('\nCreating network map...')

    G = pyyed.Graph()
    # f = plt.figure()

    bn = 'base'
    G.add_node(bn, label='base')

    tree = ET.parse('scanio.xml')
    root = tree.getroot()
    subnets = root.findall('subnet')
    for sub in subnets:
        rd = sub.findtext('pivot')
        sa = sub.findtext('subnet-address')
        sn = sub.findtext('subnet-name')

        subnetText = 'Subnet:\n{0}\n{1}'.format(sa, sn)

        G.add_node(sa, label=subnetText, shape="roundrectangle")
        G.add_edge(bn, sa, label=get_ip_address(sa), arrowhead="none")
        hosts = sub.findall('host')
        plist = list()
        for h in hosts:
            portnums = 'Ports:'
            addy = h.find('address').text
            ports = h.findall('port')
            hostname = h.find('hostname').text
            for p in ports:
                plist.append(int(p.findtext('number')))

            for var in sorted(plist):
                spacelen = 5 - len(str(var))
                port = str(var)+' '*spacelen
                for b in root.findall('./subnet/[subnet-address = "'+sa+'"]/host/[address = "'+addy+'"]/port/[number = "'+str(var)+'"]/banner'):
                    if b.text:
                        banner = b.text
                        portext = '{0} --> {1}'.format(port, banner[:10])   
                    else:
                        portext = '{0}     {1}'.format(port, ' '*20)
                portnums = '{0}\n{1}'.format(portnums, portext)
                plist.remove(var)  

            if hostname == None:
                hostname = 'Hostname Unknown'
            nodeText = '{0}\n{1}\n{2}'.format(addy, hostname, portnums)
            G.add_node(addy, label=nodeText, shape="roundrectangle")
            G.add_edge(sa, addy, arrowhead="none")
            
 
    with open('scanio.graphml', 'w') as fp:
        fp.write(G.get_graph())

    print('Complete!')
    return

def sortXML(addy):
    if len(addy.split('.')) > 3:
        laddy = addy.split('.')
        naddy = '{0}.{1}.{2}'.format(laddy[0], laddy[1], laddy[2])
    else:
        naddy = addy

    tree = ET.parse('scanio.xml')
    root = tree.getroot()
    subnetstr = './subnet/[subnet-address = "'+naddy+'"]'
    subnet = root.find(subnetstr)
    subnethosts = subnet.findall('host')
    if subnethosts:

        #sort ports
        pdata = []
        tree = ET.parse('scanio.xml')
        root = tree.getroot()
        subnetstr = './subnet/[subnet-address = "'+naddy+'"]'
        subnet = root.find(subnetstr)
        subnethosts = subnet.findall('host')
        for host in subnethosts:            
            ports = host.findall('port')
            hostadd = host.find('address')
            hostaddt = hostadd.text
            hostaddl = hostaddt.split('.')
            hostaddstr = ''.join(hostaddl)
            if ports == [] or ports == None:
                subnet.remove(host)
                indent(root)
                tree.write("scanio.xml")
            else:
                for numv in ports:
                    key = numv.findtext("number")
                    pdata.append((int(hostaddstr+key), numv))
        pdata.sort()
        subnethosts[:] = [item[-1] for item in pdata]     
        indent(root)
        tree.write("scanio.xml")
     
        return 0
    else:
        return 1

def printall(addy):
    if len(addy.split('.')) > 3:
        laddy = addy.split('.')
        naddy = '{0}.{1}.{2}'.format(laddy[0], laddy[1], laddy[2])
        ip = '{0}.{1}.{2}.{3}'.format(laddy[0], laddy[1], laddy[2], laddy[3])

        tree = ET.parse('scanio.xml')
        root = tree.getroot()
        subnetstr = './subnet/[subnet-address = "'+naddy+'"]'
        subnet = root.find(subnetstr)
        subnethosts = subnet.findall('host')
        if subnethosts:
            plist = list()
            introptext = '\r---------------'

            if ip == get_ip_address(naddy):
                introptext = '{0}\n{1} (current host)'.format(introptext, ip)
            else:
                introptext = '{0}\n{1}'.format(introptext, ip)

            for p in root.findall('./subnet/[subnet-address = "'+naddy+'"]/host/[address = "'+ip+'"]/port/number'):
                plist.append(int(p.text))

            if plist:
                print('\r{0}'.format(' '*70))
                print(introptext)

                for pp in sorted(plist):
                    spacelen = 5 - len(str(pp))
                    printtext = '|__ {0}'.format(pp)
                    endlen = 70 - len(printtext)
                    printtext = printtext + ' '*endlen
                    for b in root.findall('./subnet/[subnet-address = "'+naddy+'"]/host/[address = "'+ip+'"]/port/[number = "'+str(pp)+'"]/banner'):
                        if b.text:
                            banner = b.text
                            printtext = '|__ {0} {1}-> {2}\n'.format(pp, '-'*spacelen, banner[:50])
                    
                    for r in root.findall('./subnet/[subnet-address = "'+naddy+'"]/host/[address = "'+ip+'"]/port/[number = "'+str(pp)+'"]/robust'):
                        if r.text:
                            rb = r.text.splitlines()
                            rb = '\n     '.join(rb)
                            printtext = '|__ {0}'.format(rb)

                    print('{0}'.format(printtext))          
                    plist.remove(pp)
    else:
        naddy = addy
        tree = ET.parse('scanio.xml')
        root = tree.getroot()
        subnetstr = './subnet/[subnet-address = "'+naddy+'"]'
        subnet = root.find(subnetstr)
        subnethosts = subnet.findall('host')
        if subnethosts:
            hlist = list()
            plist = list()
            for h in root.findall('./subnet/[subnet-address = "'+naddy+'"]/host/address'):
                hlist.append(h.text)
            ip_list = [ip.strip() for ip in hlist]
            for ip in sorted(ip_list, key = lambda ip: ( int(ip.split(".")[0]), int(ip.split(".")[1]), int(ip.split(".")[2]), int(ip.split(".")[3]))):
                print('\r{0}'.format(' '*70))
                print('\r---------------{0}'.format(' '*55))
                if ip == get_ip_address(addy):
                    print('{0} (current host)'.format(ip))
                else:
                    print(ip)
                for p in root.findall('./subnet/[subnet-address = "'+naddy+'"]/host/[address = "'+ip+'"]/port/number'):
                    plist.append(int(p.text))
                for pp in sorted(plist):
                    spacelen = 5 - len(str(pp))
                    printtext = '|__ {0}'.format(pp)
                    for b in root.findall('./subnet/[subnet-address = "'+naddy+'"]/host/[address = "'+ip+'"]/port/[number = "'+str(pp)+'"]/banner'):
                        if b.text:
                            banner = b.text
                            printtext = '|__ {0} {1}-> {2}\n'.format(pp, '-'*spacelen, banner[:50])
                    
                    for r in root.findall('./subnet/[subnet-address = "'+naddy+'"]/host/[address = "'+ip+'"]/port/[number = "'+str(pp)+'"]/robust'):
                        if r.text:
                            rb = r.text.splitlines()
                            rb = '\n     '.join(rb)
                            printtext = '|__ {0}'.format(rb)

                    print('{0}'.format(printtext))          
                    plist.remove(pp)
    return

def clearLog():
    now = datetime.now()
    dt_string = now.strftime("%Y%m%d%H%M%S")
    with open("scanio.xml", "w") as f:
        f.write('<?xml version="1.0"?>\n')
        f.write('<scan>\n')
        f.write('</scan>')
        f.close()
    return

def newScan(addy):
    tree = ET.parse('scanio.xml')
    root = tree.getroot()
    subnetstr = './subnet/[subnet-address = "'+addy+'"]'
    subnet = root.find(subnetstr)
    if subnet == None:
        addSubnet(addy)
    return

def init(args):
    ''' store the counter for later use '''
    global currcount
    currcount = args

progtext = None        
totalscans = 0
secs = None
tic = None
currcount = Value('i', 0)
if os.path.exists('scanio.xml') == False:
    clearLog()
lock = Lock()

if __name__ == '__main__':
    scanInfo = initiate()
    scanType = scanInfo[0]
    net = scanInfo[1]
    final_range = scanInfo[2]
    final_ports = scanInfo[3]
    totalscans = scanInfo[4]
    printnet = scanInfo[5]
    clearlog = scanInfo[6]
    netmap = scanInfo[7]
    robust = scanInfo[8]

    contVar = input('Continue? Y/N (default y): ')
    if contVar != 'Y' and contVar != 'Yes' and contVar != 'yes' and contVar != 'y' and contVar != '':
        sys.exit(2)
    
    if clearlog:
        clearLog()
    
    newScan(net)

    Timer()
    update_progress()
    try:
        for i in final_range:
            addy = str(net) + "." + str(i)
            with Pool(initializer = init, initargs = (currcount, ), processes=20, maxtasksperchild=100) as pool:
                results = pool.starmap_async(scanType, zip(repeat(str(addy)+':'+str(robust)), final_ports))
                results.wait()

            logVars = sortXML(addy)
            if logVars == 1:
                pass
            else:
                printall(addy)

    except KeyboardInterrupt:
        print('\n\n\t\t!!! SCAN INTERRUPTED !!!\n')
        time.sleep(0.2)
        logVars = sortXML(printnet)
        if logVars == 1:
            print('\nNo Hosts Found...')
            sys.exit(2)
        else:
            # printall(printnet)
            if netmap:
                netgraph()
            sys.exit(2)

    currcount.value = totalscans
    update_progress()
    time.sleep(0.3)
    print('\n\n\t\t*** SCAN COMPLETE *** ')
    logVars = sortXML(printnet)
    if logVars == 1:
        print('\nNo Hosts Found...')
        sys.exit(2)
    else:
        # printall(printnet)
        if netmap:
            netgraph()
    
