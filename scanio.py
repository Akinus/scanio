#!/usr/bin/env python3
########################################################################
# This header measures out 72 Characters of line length
# File Name : test.py
# Author : Gabriel Akonom
# Creation Date : 24Sep2020
# Last Modified : Thu Sep 24 14:32:40 2020
# Description:
#
########################################################################

from multiprocessing import Process, set_start_method, Pool, Value, Lock, Manager, get_context
from xml.etree import ElementTree as ET
from xml.dom import minidom
from datetime import datetime
from itertools import repeat
import subprocess as sub
from subprocess import STDOUT, check_output
from re import search
import concurrent.futures
import ctypes
import functools
import time
import socket
import threading
import argparse
import sys
import os
import re
import shutil
from curses import wrapper
import curses
import traceback
import multiprocessing
import os
import time

#This portion will check for pyyed and prompt user to install it if not already
try:
    import pyyed
except:
    try:
        while True:
            choice = input('Pyyed library not found but is needed. Install? \'Y\'es or \'N\'o?\n:')
            if choice.lower() == 'y':
                sub.call('pip3 install pyyed',shell=True)
                import pyyed
                break
            elif choice.lower() == 'n':
                exit()
            else:
                continue
    except Exception as e:
        print(e)
        exit()

class scanjobs(object):
    def __init__(self, file='scanio.xml'):
        self.rootfile = file
        self.file = file
        pass
    
    def get_ip_address(self, net):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((net + '.1', 30100))
        return s.getsockname()[0]

    def newScan(self, addy):
        tree = ET.parse(self.rootfile)
        root = tree.getroot()
        subnetstr = './subnet/[subnet-address = "'+addy+'"]'
        subnet = root.find(subnetstr)
        if subnet == None:
            self.addSubnet(addy)
    
    def ulimit(self):
        try:
            tcp_args = ['ulimit -n']
            tcp_res = sub.Popen(tcp_args, stdout = sub.PIPE, stderr = sub.PIPE, universal_newlines = True, shell = True)
            tcp_res.wait()
            softlimit, err = tcp_res.communicate()
            tcp_res.kill()
            # tcp_args = ['nc -nvzw1 '+str(addy)+' '+str(tp)+' 2>&1']
            # result = check_output(['nc -nvzw1 '+str(addy)+' '+str(tp)+' 2>&1'], stderr=STDOUT, timeout=0.3)
        except:
            softlimit = 1024
        
        try:
            tcp_args = ['ulimit -n -H']
            tcp_res = sub.Popen(tcp_args, stdout = sub.PIPE, stderr = sub.PIPE, universal_newlines = True, shell = True)
            tcp_res.wait()
            hardlimit, err = tcp_res.communicate()
            tcp_res.kill()
            # tcp_args = ['nc -nvzw1 '+str(addy)+' '+str(tp)+' 2>&1']
            # result = check_output(['nc -nvzw1 '+str(addy)+' '+str(tp)+' 2>&1'], stderr=STDOUT, timeout=0.3)
        except:
            hardlimit = 1024
        
        try:
            tcp_args = ['ulimit -n '+hardlimit]
            tcp_res = sub.Popen(tcp_args, stdout = sub.PIPE, stderr = sub.PIPE, universal_newlines = True, shell = True)
            tcp_res.wait()
            result2, err = tcp_res.communicate()
            tcp_res.kill()
            # tcp_args = ['nc -nvzw1 '+str(addy)+' '+str(tp)+' 2>&1']
            # result = check_output(['nc -nvzw1 '+str(addy)+' '+str(tp)+' 2>&1'], stderr=STDOUT, timeout=0.3)
        except:
            result2 = 'Error'
        
        if result2 == 'Error':
            return softlimit

        try:
            tcp_args = ['ulimit -n']
            tcp_res = sub.Popen(tcp_args, stdout = sub.PIPE, stderr = sub.PIPE, universal_newlines = True, shell = True)
            tcp_res.wait()
            softlimit, err = tcp_res.communicate()
            tcp_res.kill()
            # tcp_args = ['nc -nvzw1 '+str(addy)+' '+str(tp)+' 2>&1']
            # result = check_output(['nc -nvzw1 '+str(addy)+' '+str(tp)+' 2>&1'], stderr=STDOUT, timeout=0.3)
        except:
            softlimit = 1024
        
        return softlimit

    def initiate(self):
        show = display()
        if os.path.exists(self.file) == False:
            io.clearLog(io())
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
        uinput.add_argument("-p-", "--allports", help = "Shortcut to scan all ports 1-65535", action="store_true")
        uinput.add_argument("-c", "--clearlog", help = "Clears the log and starts fresh.", action="store_true")
        uinput.add_argument("-f", "--fast", help = "Performs a fast scan using netcat vs the default /dev/tcp.  This option does have \
                                                    the potential to miss some ports.  REQUIRES NETCAT to be installed. \
                                                    ", action="store_true")
        uinput.add_argument("-en", "--enumerate", help = "Performs Nikto, Gobuster, http-vuln NMAP, smb-vuln NMAP, \
                                                    WPScan, and Searchsploit scans on found pertinent services. \
                                                    REQUIRES THOSE PROGRAMS AND SECLISTS to be installed or these scans will fail. \
                                                    ", action="store_true")                                            
        uinput.add_argument("--show", help = "Shows the currently logged results for the address.  When used with --map \
                                                this will recreate the network map also", action="store_true")
        uinput.add_argument("-m", "--map", help = "Creates a network map to a .graphml file \
                                                    Download yEd to edit scanio.graphml from https://www.yworks.com/products/yed", action="store_true")
        uinput.add_argument("-nC", "--cnote", help = "Creates a new CherryTree note file with pre-determined template", action="store_true")
        uinput.add_argument("-nZ", "--znote", help = "Creates a new Zim folder structure and templated notes", action="store_true")
        uinput.add_argument("-pc", "--proxychains", help = "Changes the network saturation to try and avoid the \
                                                    'too many files open' error", action="store_true")
        uinput.add_argument("-rb", "--robust", help = "Runs NMAP -A on found ports. WARNING: THIS WILL DRASTICALLY SLOW \
                                                    DOWN THE SCAN. ***REQUIRES NMAP TO BE INSTALLED***", action="store_true")                                                

        ipstart = 1
        ipend = 254
        fulladd = False
        clearlog = False
        netmap = False
        robust = False
        cNote = False
        zNote = False
        timeout = 2
        prints = []
        allports = False
        enum = False

        opts = uinput.parse_args()

        net = opts.address
        if opts.show:
            printext = show.printall(net)[0]
            print(printext)
            if opts.map:
                io.netgraph(io())
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
                prints.append('You entered a full address, and/or provided an end/start host, and/or provided a range (or a combination thereof)')
                sys.exit(2)

        if opts.range:
            iprange = opts.range
            if opts.end != None and len(net.split('.')) <= 3:
                prints.append('You entered a full address, and/or provided an end/start host, and/or provided a range (or a combination thereof)')
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
                final_range = self.parseRange(iprange)
        else:
            final_range = set()
            for p in range(ipstart,ipend+1):
                final_range.add(p)

        if opts.allports:
            uports = '1-65535'
            pports = uports
        elif opts.ports:
            uports = opts.ports
            pports = uports
        else:
            uports = "20-25,50-53,67-69,80,110,119,123,135-139,143,161,162,389,443,989,990,3389,2222,4444,8080"
            pports = 'from https://rb.gy/x86g6c (plus some custom): \n|    {0}'.format(uports)
        final_ports = self.parseRange(uports)

        hostnum = len(final_range)
        if hostnum <= 1:
            phostvar = 'Scanning host {0}.{1}'.format(net, str(min(final_range)))
        elif hostnum > 1:
            phostvar = 'Scanning hosts {0}.{1} to {0}.{2}'.format(net, str(min(final_range)), str(max(final_range)))
        totalscans = hostnum*len(final_ports)
        
        if opts.fast:
            operation = 'callScanNC'
            totaltime = totalscans / 18
        elif os.name == 'nt':
            operation = 'callScanW'
        else:
            operation = 'callScanP'
            totaltime = totalscans / 12

        mon, sec = divmod(float(totaltime), 60)
        mon = "{:.0f}".format(mon)
        sec = "{:.0f}".format(sec)

        prints.append('| {0} Total Scans. Approximately {1}m {2}s'.format(totalscans, mon, sec))
        prints.append('|--> {0}'.format(phostvar))
        prints.append('|--> Scanning ports {0}'.format(pports))        
            
        hosts = []
        if fulladd == True:
            printnet = '{0}.{1}'.format(net, min(final_range))
            hosts.append(printnet)
        else:
            printnet = net
            hosts = list(((net+'.'+str(h)) for h in final_range))

        if opts.map:
            prints.append('|--> Will create a network map to scanio.graphml in current directory...')
            prints.append('|    Download yEd to edit scanio.graphml from https://www.yworks.com/products/yed')
            netmap = True

        if opts.cnote:
            prints.append('|--> Will create/modify a CherryTree file for each/this host in current directory...')
            cNote = True

        if opts.znote:
            prints.append('|--> Will create/modify Directories for notes (Zim) file for each/this host in current directory...')
            zNote = True
        
        if opts.clearlog:
            prints.append('|--> The current log will be cleared and recreated as well as the TCP enumeration of each host.')
            clearlog = True
                    
        if opts.robust:
            prints.append('|--> Will perform NMAP Robust scan on found ports')
            robust = True
        
        if opts.proxychains:
            prints.append('|--> Will adjust traffic to avoid proxychains network saturation')
            timeout = 4

        if opts.enumerate:
            prints.append('|--> Will use all pertinent enumeration scans. ***WARNING*** Go grab some lunch, this will probably take a while.')
            enum = True

        plimit = self.ulimit()
        prints.append('File Limit = {0}'.format(plimit))
        for p in prints:
            print(p)
        
        contVar = input('Continue? Y/N (default y): ')
        if contVar != 'Y' and contVar != 'Yes' and contVar != 'yes' and contVar != 'y' and contVar != '':
            sys.exit(2)

        return operation, net, final_range, final_ports, totalscans, printnet, clearlog, netmap, robust, cNote, zNote, fulladd, timeout, hosts, enum
    
     #http://thoughtsbyclayg.blogspot.com/2008/10/parsing-list-of-numbers-in-python.html
    def parseRange(self, nputstr=""):
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

    def seconds(self, _secs):
        _secs.value += 1
        time.sleep(2)
        while True:
            _secs.value += 1
            time.sleep(1)
    
    def totalcount(self, hosts, ports):
        retvals = []
        for h in hosts:
            nhl = zip(repeat(str(h)), ports)
            for nh in nhl:
                retvals.append(nh)
        tc = len(retvals)
        return tc, retvals

    def start(self):
        ##SET GLOBAL VARIABLES
        global secs
        global count
        global flag
        global secs
        global count
        global flag
        global progtext
        global lock
        global counter_lock
        global totalcount
        lock = Lock()
        manager = multiprocessing.Manager()
        count = manager.Value('i', 0)
        counter_lock = manager.Lock()  # pylint: disable=no-member
        # count = Value('i', 1)
        secs = Value('i', 0)
        flag = Value('i', 0)
        totalcount = Value('i', 0)
        progtext = Value(ctypes.c_wchar_p, ' ')
        currcount = count

        write = io()
        show = display()
        scanInfo = self.initiate()
        #return operation, net, final_range, final_ports, totalscans, printnet, clearlog, netmap, robust, cNote, zNote, fulladd, proxy, hosts
        scanType = scanInfo[0]
        net = scanInfo[1]
        final_range = scanInfo[2]
        ports = scanInfo[3]
        totalscans = scanInfo[4]
        printnet = scanInfo[5]
        clearlog = scanInfo[6]
        netmap = scanInfo[7]
        robust = scanInfo[8]
        cnote = scanInfo[9]
        znote = scanInfo[10]
        fulladd = scanInfo[11]
        timeout = scanInfo[12]
        hosts = scanInfo[13]
        enum = scanInfo[14]
        
        # print(show.printall(net)[3])
        # sys.exit()

        if clearlog:
            write.clearLog()
        
        self.newScan(net)
        
        ####################### BEGIN PROCESSING
        if len(net.split('.')) > 3:
            threeoctet = '{0}.{1}.{2}'.format(net.split('.')[0], net.split('.')[1], net.split('.')[2])
            ##REMOVE ADDRESS IF IT EXISTS
            tree = ET.parse(self.rootfile)
            root = tree.getroot()
            addystr = './subnet/[subnet-address = "'+threeoctet+'"]/host/[address = "'+net+'"]'
            subnetstr = './subnet/[subnet-address = "'+threeoctet+'"]'
            subnet = root.find(subnetstr)
            subnethost = subnet.find('host/[address = "'+net+'"]')
            addy = root.find(addystr)
            if addy == None:
                pass
            else:
                subnet.remove(subnethost)
                show.indent(root)
                tree.write(self.file)
        else:
            threeoctet = net
            ##ADD SUBNET IF IT DOES NOT EXIST
            tree = ET.parse(self.rootfile)
            root = tree.getroot()
            subnetstr = './subnet/[subnet-address = "'+threeoctet+'"]'
            subnet = root.find(subnetstr)
            if subnet == None:
                self.addSubnet(threeoctet)
            else:
                root.remove(subnet)
                show.indent(root)
                tree.write(self.file)
                self.addSubnet(threeoctet)

        ##DETERMINE TOTAL NUMBER OF SCANS
        totalcount.value = self.totalcount(hosts, ports)[0]
    
        ##START RESULTS CATCHER
        res = io()
        manager = Manager()
        q = manager.Queue()
        p = Process(target= res.process_results, args=(q, currcount, totalcount, progtext, net, znote, netmap))
        p.start()
        
        if scanType == 'callScanNC':
            func = functools.partial(self.callScanNC, timeout, currcount, q, robust, enum)
        else:
            func = functools.partial(self.callScanP, timeout, currcount, q, robust, enum)

        ##BEGIN SCAN THREADS
        addys = self.totalcount(hosts, ports)[1]
        pool = multiprocessing.Pool(processes=100, maxtasksperchild=100)
        results = pool.map_async(func, addys)
        # scanPool = concurrent.futures.ThreadPoolExecutor(max_workers=200)
        

        try:
            # time.sleep(5)
            # print(results._number_left)
            # sys.exit()

            window = _window()
            ##BEGIN UPDATING WINDOW
            mypad_pos = window.mypad_pos
            # with counter_lock:
            #     currcount.value += 1


            ###START THREADS FOR PROGRESS TIME AND SCREEN
            thread = threading.Thread(target=self.seconds, args=(secs,))
            thread.daemon = True                            # Daemonize thread
            thread.start()                                  # Start the execution


            while currcount.value < totalcount.value:
                # tsize = str(shutil.get_terminal_size((80, 20))).split(',')[0].split('=')[1]
                remaining = currcount.value
                progress = remaining / totalcount.value
                if float(secs.value) > 0:
                    pps = remaining / float(secs.value)
                    pps = "{:.0f}".format(pps)
                mon, sec = divmod(float(secs.value), 60)
                mon = "{:.0f}".format(mon)
                sec = "{:.0f}".format(sec)
                barLength = round(window.width / 4) # Modify this to change the length of the progress bar
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
                # printext = self.printall(net)
                update = "Percent: [{0}] {1}% {2} {3}/{4}. {5}m {6}s spent. ~{7} ports/s    ".format( "#"*block + "-"*(barLength-block), smallProgress, status, currcount.value, totalscans, mon, sec, pps)
                progtext.value = show.printall(net)[0]
                length = len(str(progtext.value).splitlines()) + 10
                window.pad.resize(length, window.width)
                window.pad.addstr(1, 1, update)
                window.pad.addstr(2, 1, progtext.value)
                window.pad.refresh(mypad_pos, 0, 1, 1, window.height, window.width)
                
                
                ## CATCH KEYS
                ch = window.screen.getch()
                if ch == curses.KEY_DOWN:
                    mypad_pos += 1
                    window.pad.refresh(mypad_pos, 0, 1, 1, window.height, window.width)
                elif ch == curses.KEY_UP:
                    mypad_pos -= 1
                    window.pad.refresh(mypad_pos, 0, 1, 1, window.height, window.width)
                elif ch == ord('q'):
                    raise KeyboardInterrupt
                    # print("You'll have to press ctrl-c to deliver the death blow...")
                else:
                    window.pad.refresh(mypad_pos, 0, 1, 1, window.height, window.width)
                
                time.sleep(0.01)
            # found = results.get()
            # found = list(dict.fromkeys(found))
            time.sleep(2)
            window.pad.clear()
            while True:
                progress = 1
                smallProgress = "{:.1f}".format(progress*100)
                update = "Percent: [{0}] {1}% {2} {3}/{4}. {5}m {6}s spent. ~{7} ports/s\n{8}\n{9} \
".format( "#"*block + "-"*(barLength-block), smallProgress, status, currcount.value, totalscans, mon, sec, pps, '***SCAN COMPLETE!***', 'Press q to exit this window...')
                progtext.value = show.printall(net)[0]
                length = len(str(progtext.value).splitlines()) + 10
                window.pad.resize(length, window.width)
                ch = window.screen.getch()
                if ch == curses.KEY_DOWN:
                    mypad_pos += 1
                    window.pad.refresh(mypad_pos, 0, 1, 1, window.height, window.width)
                elif ch == curses.KEY_UP:
                    mypad_pos -= 1
                    window.pad.refresh(mypad_pos, 0, 1, 1, window.height, window.width)
                elif ch == ord('q'):
                    raise SystemExit
                else:
                    window.pad.addstr(1, 1, update)
                    window.pad.addstr(4, 1, progtext.value)
                    window.pad.refresh(mypad_pos, 0, 1, 1, window.height, window.width)
                time.sleep(0.01)

            ##CLOSE POOL AND CATCHER
        except Exception as e:
            window.kill()
            print('Exception...\n{0}'.format(e))
            if p.is_alive:
                p.terminate()            
        
        except KeyboardInterrupt:
            window.kill()
            print("User cancelled the scan!")
            if p.is_alive:
                p.terminate()
        
        except SystemExit:
            window.kill()
            print('System Exit...')
            if p.is_alive:
                p.terminate()

        finally:
            print('\n\n########################### RESULTS #######################')

            results = show.printall(net)[0]
            print(results)
            print('\n############################ END ##########################\n')
            sys.tracebacklimit=0
            
    def callScanNC(self, timeout, currcount, q, robust, enum, addys):
        addy = addys[0]
        tp = addys[1]
        retval = None
        # print('Scanning {0}:{1}. Timeout of {2}'.format(addy, tp, timeout))
        # time.sleep(5)
        # q.put('Scanning {0}'.format(addy))
        try:
            tcp_args = ['timeout '+str(timeout+1)+' /bin/bash -c "nc -nvz -w '+str(timeout+1)+' '+str(addy)+' '+str(tp)+' 2>&1"']
            tcp_res = sub.Popen(tcp_args, stdout = sub.PIPE, stderr = sub.PIPE, universal_newlines = True, shell = True)
            tcp_res.wait(timeout)
            result, err = tcp_res.communicate()
            tcp_res.kill()
            # tcp_args = ['nc -nvzw1 '+str(addy)+' '+str(tp)+' 2>&1']
            # result = check_output(['nc -nvzw1 '+str(addy)+' '+str(tp)+' 2>&1'], stderr=STDOUT, timeout=0.3)
        except (Exception, KeyboardInterrupt, SystemExit):
            result = 'Encountered and error while scanning {0}'.format(addy)
            # raise KeyboardInterrupt
            # print(result, end='\r')

        if "open" in result or "succ" in result:
            retval = '{0}'.format(addy)
            ##NMAP scan
            if robust:
                robust = self.robustScan(addy, tp)
            else:
                robust = ''
            #Banner Grab
            if robust == '':
                banner = self.bannerGrab(timeout, addy, tp, currcount)
            else:
                banner = robust[13:100].replace('\n', ' ').replace('   ', '')
            addyStr = './subnet/host/[address = "'+str(addy)+'"]'
            tree = ET.parse(self.file)
            root = tree.getroot()
            hoste = root.find(addyStr)
            if hoste == None:
                self.addHost(addy)
                self.addPort(addy, tp, banner, robust)
            else:
                self.addPort(addy, tp, banner, robust)
            
            if enum:
                poolx = concurrent.futures.ThreadPoolExecutor(max_workers=6)
                with poolx:
                    if 'http' in banner or 'HTTP' in banner:
                        domain = 'http://'
                        poolx.submit(self.http_vulnScan, addy, tp)
                        poolx.submit(self.gobusterScan, domain, addy, tp)

            io.sortXML(io(), addy)
            
            # print(result)
        q.put(1)    
        # with counter_lock:
        #     currcount.value += 1
        return retval

    def callScanP(self, timeout, currcount, q, robust, enum, addys):
        addy = addys[0]
        tp = addys[1]
        retval = None
        # print('Scanning {0}:{1}. Timeout of {2}'.format(addy, tp, timeout))
        # time.sleep(5)
        # q.put('Scanning {0}'.format(addy))
        try:
            tcp_args = ['timeout '+str(timeout)+' /bin/bash -c "exec echo > /dev/tcp/'+str(addy)+'/'+str(tp)+'";retval=$?;echo $retval']
            tcp_res = sub.Popen(tcp_args, stdout = sub.PIPE, stderr = sub.PIPE, universal_newlines = True, shell = True)
            tcp_res.wait(timeout)
            result, err = tcp_res.communicate()
            tcp_res.kill()
        except (Exception, KeyboardInterrupt, SystemExit):
            result = 'Encountered and error while scanning {0}'.format(addy)
            # raise KeyboardInterrupt

        if result == '0\n':
            retval = '{0}'.format(addy)
            ##NMAP scan and banner Grab
            if robust:
                robust = self.robustScan(addy, tp)
                banner = robust[13:100].replace('\n', ' ').replace('   ', '')
            else:
                robust = ''
                banner = self.bannerGrab(timeout, addy, tp, currcount)
            addyStr = './subnet/host/[address = "'+str(addy)+'"]'
            tree = ET.parse(self.file)
            root = tree.getroot()
            hoste = root.find(addyStr)
            if hoste == None:
                self.addHost(addy)
                self.addPort(addy, tp, banner, robust)
            else:
                self.addPort(addy, tp, banner, robust)
            
            
            if enum:
                poolx = concurrent.futures.ThreadPoolExecutor(max_workers=4)
                with poolx:
                    if 'http' in banner or 'HTTP' in banner:
                        domain = 'http://'
                        poolx.submit(self.http_vulnScan, addy, tp)
                        poolx.submit(self.gobusterScan, domain, addy, tp)
                    
                    # httpVuln = Process(target= self.http_vulnScan, args=(addy, tp)) 
                    # httpVuln.start()

                # while flags != 11:
                #     if gobuster:
                #         self.addGobuster(addy, tp, gobuster)
                #         flags += 1
                #         gobuster.join()
                #         gobuster.close()
                #     if httpVuln:
                #         self.addhttp_vuln(addy, tp, httpVuln)
                #         flags += 10
                #         httpVuln.join()
                #         gobuster.close()


            io.sortXML(io(), addy)
        q.put(addy)
        # with counter_lock:
        # currcount.value += 1
        # print(result)
        return retval

    def bannerGrab(self, timeout, addy, port, currcount):
        try:
            tcp_args = 'timeout '+str(timeout)+' bash -c "exec 2<>/dev/tcp/'+str(addy)+'/'+str(port)+';echo EOF>&2; cat<&2"'
            tcp_res = sub.Popen(tcp_args, stdout = sub.PIPE, stderr = sub.PIPE, universal_newlines = True, shell = True)
            tcp_res.wait()
            out, err = tcp_res.communicate()
            tcp_res.kill()
        except (Exception, KeyboardInterrupt, SystemExit):
            out = 'BannerError.'
            # raise Exception

        if search('concurrent connection', out):
            out = ''


        return out.partition('\n')[0]

    def robustScan(self, addy, port):
        try:
            tcp_args = 'timeout 30 bash -c "nmap -T4 -A -Pn ' + str(addy) + ' -p ' + str(port) + '"'
            tcp_res = sub.Popen(tcp_args, stdout = sub.PIPE, stderr = sub.PIPE, universal_newlines = True, shell = True)
            tcp_res.wait()
            out, err = tcp_res.communicate()
            tcp_res.kill()
        except (Exception, KeyboardInterrupt, SystemExit):
            out = 'NMAP-Error.'
            # raise Exception

        if search('concurrent connection', out):
            out = ''
        
        rbl = out.splitlines()
        if len(rbl) > 5:
            out = '\n'.join(rbl[5:-3])
        else:
            out = ''
        return out

    def http_vulnScan(self, addy, port):
        try:
            tcp_args = 'timeout 120 bash -c "nmap -T4 --script=http-vuln* -Pn ' + str(addy) + ' -p ' + str(port) + '"'
            tcp_res = sub.Popen(tcp_args, stdout = sub.PIPE, stderr = sub.PIPE, universal_newlines = True, shell = True)
            tcp_res.wait(121)
            out, err = tcp_res.communicate()
            tcp_res.kill()
        except (Exception, KeyboardInterrupt, SystemExit):
            out = 'NMAP-Error.'
            # raise Exception

        if search('concurrent connection', out):
            out = ''
        self.addhttp_vuln(addy, port, out)
        return

    def gobusterScan(self, domain, addy, port):
        try:
            tcp_args = 'timeout 180 bash -c "gobuster dir -u '+str(domain)+str(addy)+':'+str(port)+' -t 35 --wordlist=\'/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt\'"'
            tcp_res = sub.Popen(tcp_args, stdout = sub.PIPE, stderr = sub.PIPE, universal_newlines = True, shell = True)
            tcp_res.wait(181)
            out, err = tcp_res.communicate()
            tcp_res.kill()
        except (Exception, KeyboardInterrupt, SystemExit):
            out = err
            # print(err)
            # raise Exception

        if search('concurrent connection', out):
            out = ''
        
        self.addGobuster(addy, port, out)
        return
    
    def addSubnet(self, addy):
        pivot = scanjobs.get_ip_address(scanjobs(), addy)
        tree = ET.parse(self.file)
        root = tree.getroot()
        newSN = ET.SubElement(root, 'subnet')
        newaddy = ET.SubElement(newSN, 'subnet-address')
        newaddy.text = addy
        newpivot = ET.SubElement(newSN, 'pivot')
        newpivot.text = pivot
        newname = ET.SubElement(newSN, 'subnet-name')
        newname.text = ""
        display.indent(display(), root)
        tree.write(self.file)
        return

    def addHost(self, addy):
        with lock:
            sl = addy.split('.')
            subnetstr = './subnet/[subnet-address = "{0}.{1}.{2}"]'.format(sl[0], sl[1], sl[2])
            # pivotstr = './subnet/[subnet-address = "{0}.{1}.{2}"]/pivot'.format(sl[0], sl[1], sl[2])
            tree = ET.parse(self.file)
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
            display.indent(display(), root)
            tree.write(self.file)
        return
    
    def addGobuster(self, addy, port, gobuster):
        show = display()
        gobuster = gobuster.splitlines()
        gobuster = '\n'.join(gobuster[13:])
        with lock:
            sl = addy.split('.')
            subnetstr = './subnet/[subnet-address = "{0}.{1}.{2}"]'.format(sl[0], sl[1], sl[2])
            # pivotstr = './subnet/[subnet-address = "{0}.{1}.{2}"]/pivot'.format(sl[0], sl[1], sl[2])
            tree = ET.parse(self.file)
            root = tree.getroot()
            subnet = root.find(subnetstr)
            # pivot = root.find(pivotstr).text
            # if addy != pivot:
            host = subnet.find('./host/[address = "'+addy+'"]')
            newgo = ET.SubElement(host, 'gobuster')
            newgo.text = '\n====================> Gobuster for {0}:{1}\n{2}'.format(addy, port, gobuster)
            show.indent(root)
            tree.write(self.file)
        return
    
    def addhttp_vuln(self, addy, port, httpVuln):
        show = display()
        httpVuln = httpVuln.splitlines()
        httpVuln = '\n'.join(httpVuln[4:-1])
        with lock:
            sl = addy.split('.')
            subnetstr = './subnet/[subnet-address = "{0}.{1}.{2}"]'.format(sl[0], sl[1], sl[2])
            # pivotstr = './subnet/[subnet-address = "{0}.{1}.{2}"]/pivot'.format(sl[0], sl[1], sl[2])
            tree = ET.parse(self.file)
            root = tree.getroot()
            subnet = root.find(subnetstr)
            # pivot = root.find(pivotstr).text
            # if addy != pivot:
            host = subnet.find('./host/[address = "'+addy+'"]')
            newgo = ET.SubElement(host, 'httpVuln')
            newgo.text = '\n====================> httpVuln for {0}:{1}\n{2}'.format(addy, port, httpVuln)
            show.indent(root)
            tree.write(self.file)
        return
    
    def addPort(self, addy, num, banner, robust):
        with lock:
            addyStr = './subnet/host/[address = "'+str(addy)+'"]'
            tree = ET.parse(self.file)
            root = tree.getroot()
            host = root.find(addyStr)
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
                    display.indent(display(), root)
                    tree.write(self.file)
                else:
                    bannertext = portnum.find('banner')
                    if bannertext.text != banner:
                        bannertext.text = banner

                    robusttext = portnum.find('robust')
                    if robusttext.text != robust:
                        robusttext.text = robust

                    display.indent(display(), root)
                    tree.write(self.file)
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
                    display.indent(display(), root)
                    tree.write(self.file)
                else:
                    bannertext = portnum.find('banner')
                    if bannertext.text != banner:
                        bannertext.text = banner

                    robusttext = portnum.find('robust')
                    if robusttext.text != robust:
                        robusttext.text = robust

                    display.indent(display(), root)
                    tree.write(self.file)
        return

class io(object):

    def __init__(self, file = 'scanio.xml'):
        self.file = file
        self.rootfile = file
        show = display()
        pass

    def process_results(self, queue, currcount, totalcount, progtext, net, znote, graph):
        write = io()
        q = queue

        while currcount.value < totalcount.value:
            variable = q.get(True)
            if znote:
                write.newZnote(variable)

            if graph:
                write.netgraph()

            with counter_lock:
                currcount.value += 1

    def clearZNote(self, addy):
        if os.name == 'nt':
            sep = '\\'
        else:
            sep = '/'
        
        opath = os.getcwd()
        addypath = opath + sep + addy
        filename = addypath + sep + 'Enumeration' + sep + 'TCP.txt'
        if os.path.exists(filename):
            os.remove(filename)
        return

    def clearCNote(self, addy):
        filename = addy + '.ctd'
        if os.path.exists(filename) == False:
            return
        
        tree = ET.parse(filename)
        root = tree.getroot()
        tcpnode = root.find('./node[@name="'+str(addy)+'"]/node[@name="Enumeration"]/node[@name="TCP"]')
        dataNodes = tcpnode.findall('rich_text')
        if dataNodes == None:
            return
        for dn in dataNodes:
            tcpnode.remove(dn)
        display.indent(display(), root)
        tree.write(filename)
        return

    def clearLog(self):
        # now = datetime.now()
        # dt_string = now.strftime("%Y%m%d%H%M%S")
        with open(self.file, "w") as f:
            f.write('<?xml version="1.0"?>\n')
            f.write('<scan>\n')
            f.write('</scan>')
            f.close()
        return
    
    def netgraph(self):
        # print('\nCreating network map...')

        G = pyyed.Graph()
        # f = plt.figure()

        bn = 'base'
        G.add_node(bn, label='base')

        tree = ET.parse(self.file)
        root = tree.getroot()
        subnets = root.findall('subnet')
        for sub in subnets:
            # rd = sub.findtext('pivot')
            sa = sub.findtext('subnet-address')
            sn = sub.findtext('subnet-name')

            subnetText = 'Subnet:\n{0}\n{1}'.format(sa, sn)

            G.add_node(sa, label=subnetText, shape="roundrectangle")
            G.add_edge(bn, sa, label=scanjobs.get_ip_address(scanjobs(), sa), arrowhead="none")
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
                            portext = '{0} --> {1}'.format(port, banner[:20])   
                        else:
                            portext = '{0}     {1}'.format(port, ' '*30)
                    portnums = '{0}\n{1}'.format(portnums, portext)
                    plist.remove(var)  

                if hostname == None:
                    hostname = 'Hostname Unknown'
                nodeText = '{0}\n{1}\n{2}'.format(addy, hostname, portnums)
                G.add_node(addy, label=nodeText, shape="roundrectangle")
                G.add_edge(sa, addy, arrowhead="none")
                
    
        with open('scanio.graphml', 'w') as fp:
            fp.write(G.get_graph())

        # print('Complete!')
        return

    def sortXML(self, addy):
        if len(addy.split('.')) > 3:
            laddy = addy.split('.')
            naddy = '{0}.{1}.{2}'.format(laddy[0], laddy[1], laddy[2])
        else:
            naddy = addy
        # naddy = addy
        tree = ET.parse(self.file)
        root = tree.getroot()
        subnetstr = './subnet/[subnet-address = "'+naddy+'"]'
        subnet = root.find(subnetstr)
        subnethosts = subnet.findall('host')
        if subnethosts:

            #sort ports
            pdata = []
            tree = ET.parse(self.file)
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
                    display.indent(display(), root)
                    tree.write(self.file)
                else:
                    for numv in ports:
                        key = numv.findtext("number")
                        pdata.append((int(hostaddstr+key), numv))
            pdata.sort()
            subnethosts[:] = [item[-1] for item in pdata]
            addyfindstr = './subnet/[subnet-address = "'+naddy+'"]/host/[address = "'+addy+'"]'
            if root.find(addyfindstr):
                retvalue = 0
            else:
                retvalue = 1
            display.indent(display(), root)
            tree.write(self.file)
        else:
            retvalue = 1   
        return retvalue
    
    def newZnote(self, net):
        show = display()
        data = ''
        godata = ''
        httpVulndata = ''
        try:
            for h in show.printall(net)[3]:
                addy = h
                data = show.printall(h)[1]
                naddy = '{0}.{1}.{2}'.format(addy.split('.')[0], addy.split('.')[1], addy.split('.')[2])
                cherry = addy + '.ctd'
                if os.path.exists(cherry):
                    cherrylink = '[[.\\{0}|{1}]]'.format(cherry, cherry)
                else:
                    cherrylink = ' '
                paths = []
                if os.name == 'nt':
                    sep = '\\'
                else:
                    sep = '/'
                
                opath = os.getcwd()
                addypath = opath + sep + addy
                addyfile = addy + '.txt'
                ipheader = 'Content-Type: text/x-zim-wiki\nWiki-Format: zim 0.4\nCreation-Date: 2020-10-28T20:13:55-07:00\n\
        ====== ' + addy + ' ======\nCreated Wednesday 28 October 2020\n'
                with open(addyfile, 'w') as fp:
                    fp.write(ipheader)
                    fp.write(cherrylink)
                    fp.close()

                try:
                    if os.path.exists(addypath) == False:
                        os.mkdir(addypath)
                except OSError:
                    print ("Creation of the directory %s failed" % addypath)
                # else:
                    # print ("Successfully created the directory %s " % addypath)

                text='Content-Type: text/x-zim-wiki\nWiki-Format: zim 0.4\nCreation-Date: 2020-11-01T13:29:00-08:00\n\
    ====== Methodology ======\nCreated Sunday 01 November 2020\n\n\
    ==== Network Enumeration: ====\n\
    1. [[+Network_Enumeration:TCP|TCP]]\n\
    2. [[+Network Enumeration:Nikto|Nikto]]\n\
    3. [[+Network_Enumeration:Gobuster|Gobuster]]\n\
    4. [[+Network_Enumeration:NMAP|NMAP]]\n\
    5. [[+Network_Enumeration:WPScan|WPScan]]\n\
    \n\
    ==== Individual Host Enumeration ====\n\
    1. [[+Host_Enumeration:Linpeas|Linpeas.sh]]\n\
    2. [[+Host_Enumeration:Enum4Linux|Enum4Linux]]\n\
    3. [[+Host_Enumeration:Writable_Files|Writable Files]]\n\
    4. [[+Host_Enumeration:Writable Folders|Writable Folders]]\n\
    5. [[+Host_Enumeration:Running_Processes|Running Processes]]\n\
    6. [[+Host_Enumeration:Users|Users]]\n\
    7. [[+Host_Enumeration:Groups|Groups]]\n\
    8. [[+Host_Enumeration:Interesting Places and Files|Interesting Places and Files]]\n\
    9. [[+Host_Enumeration:Connections|Connections]]\n\
    10.[[+Host_Enumeration:SUID|SUID]]\n\
    \n\
    ==== Privilege Escalation ====\n\
    1. [[+Privilege Escalation:Searchsploit (exploit-db)|Searchsploit (exploit-db)]]\n\
    2. [[+Privilege Escalation:Sudo -l|Sudo -l]]\n\
    3. [[+Privilege Escalation:Metasploit|Metasploit]]\n\
    \n\
    ==== Proof ====\n\
    1. [[+Proof:Hashes|Hashes]]\n\
    2. [[+Proof:Credentials|Credentials]]\n\
    3. [[+Proof:Screenshots|Screenshots]]\n\
    4. [[+Proof:Proof-of-root Screenshots|Proof-of-root Screenshots]]'
                filepath = addypath + sep + 'Methodology.txt'
                open(filepath, 'w').write(text)

                enumpath = addypath + sep + 'Methodology' + sep + 'Network_Enumeration'
                paths.append(enumpath)

                for path in paths:
                    try:
                        if os.path.exists(path) == False:
                            os.makedirs(path)
                    except OSError:
                        print ("Creation of the directory %s failed" % path)
                    # else:
                        # print ("Successfully created the directory %s " % path)

                datapath = enumpath + sep + 'TCP.txt'
                open(datapath, 'w').write(data)

                ####### GOBUSTER ADD TEXT
                gopath = enumpath + sep + 'Gobuster.txt'
                gobusters = None
                try:
                    tree = ET.parse(self.rootfile)
                    root = tree.getroot()
                    gobusters = root.findall('./subnet/[subnet-address = "'+naddy+'"]/host/[address = "'+addy+'"]/gobuster')
                except:
                    pass
                if gobusters:
                    for g in gobusters:
                        if g.text:
                            godata = '{0}\n{1}'.format(godata, g.text)
                        else:
                            pass

                    open(gopath, 'w').write(godata)

                ######

                ####### httpVuln ADD TEXT
                http_vulnpath = enumpath + sep + 'http-vuln.txt'
                httpVulns = None
                try:
                    tree = ET.parse(self.rootfile)
                    root = tree.getroot()
                    httpVulns = root.findall('./subnet/[subnet-address = "'+naddy+'"]/host/[address = "'+addy+'"]/httpVuln')
                except:
                    pass
                if httpVulns:
                    for hv in httpVulns:
                        if hv.text:
                            httpVulndata = '{0}\n{1}'.format(httpVulndata, hv.text)
                        else:
                            pass

                    open(http_vulnpath, 'w').write(httpVulndata)
        except:
            pass
        return

    def newCnote(self, addy, data):
        # print('\nCreating Cherry Tree Note...')
        filename = addy + '.ctd'
        data = data.replace('<', '(')
        data = data.replace('>', ')')
        if os.path.exists(filename) == False:
            newCT = '<?xml version="1.0" encoding="UTF-8"?>\n<cherrytree>~<bookmarks list=""/>~ \
            <node name="'+str(addy)+'" unique_id="2" prog_lang="custom-colors" \
            tags="" readonly="0" custom_icon_id="10" is_bold="1" foreground="" \
            ts_creation="0" ts_lastsave="1496953072">\n<node name="Enumeration" \
            unique_id="17" prog_lang="custom-colors" tags="" readonly="0" \
            custom_icon_id="21" is_bold="0" foreground="" ts_creation="0" ts_lastsave="1492949452">\n \
            <node name="TCP" unique_id="26" prog_lang="custom-colors" tags="" readonly="0" \
            custom_icon_id="18" is_bold="0" foreground="" ts_creation="1492949819" ts_lastsave="1500473593">\n \
            <rich_text>'+data+'</rich_text>\n</node>\n<node name="UDP" unique_id="27" \
            prog_lang="custom-colors" tags="" readonly="0" custom_icon_id="18" \
            is_bold="0" foreground="" ts_creation="1492949826" ts_lastsave="1500473597"/>\n \
            <node name="Web Services" unique_id="18" prog_lang="custom-colors" \
            tags="" readonly="0" custom_icon_id="17" is_bold="0" foreground="" ts_creation="0" ts_lastsave="1492949605">\n \
            <node name="Nikto" unique_id="24" prog_lang="custom-colors" tags="" \
            readonly="0" custom_icon_id="18" is_bold="0" foreground="" ts_creation="1492949545" ts_lastsave="1492949578"/>\n \
            <node name="Dirb\DirBuster" unique_id="25" prog_lang="custom-colors" tags="" \
            readonly="0" custom_icon_id="18" is_bold="0" foreground="" ts_creation="1492949554" ts_lastsave="1500473690"/>\n \
            <node name="WebDav" unique_id="33" prog_lang="custom-colors" tags="" readonly="0" \
            custom_icon_id="18" is_bold="0" foreground="" ts_creation="1500473692" ts_lastsave="1500473698"/>\n \
            <node name="CMS" unique_id="34" prog_lang="custom-colors" tags="" readonly="0" \
            custom_icon_id="18" is_bold="0" foreground="" ts_creation="1500473700" ts_lastsave="1500473703"/>\n \
            </node>\n<node name="Other Services" unique_id="20" prog_lang="custom-colors" tags="" \
            readonly="0" custom_icon_id="44" is_bold="0" foreground="" ts_creation="0" ts_lastsave="1500473607">\n \
            <node name="SMB" unique_id="21" prog_lang="custom-colors" tags="" readonly="0" \
            custom_icon_id="0" is_bold="0" foreground="" ts_creation="1500473455" ts_lastsave="1500473619"/>\n \
            <node name="SNMP" unique_id="29" prog_lang="custom-colors" tags="" readonly="0" \
            custom_icon_id="0" is_bold="0" foreground="" ts_creation="1500473619" ts_lastsave="1500473631"/>\n \
            <node name="DB" unique_id="31" prog_lang="custom-colors" tags="" readonly="0" \
            custom_icon_id="0" is_bold="0" foreground="" ts_creation="1500473622" ts_lastsave="1500473677"/>\n \
            <node name="Other" unique_id="32" prog_lang="custom-colors" tags="" readonly="0" \
            custom_icon_id="0" is_bold="0" foreground="" ts_creation="1500473623" ts_lastsave="1500473681"/>\n \
            </node>\n</node><node name="Exploitation" unique_id="22" prog_lang="custom-colors" \
            tags="" readonly="0" custom_icon_id="22" is_bold="0" foreground="" ts_creation="0" ts_lastsave="1500474629">\n \
            <rich_text weight="heavy">Service Exploited:\n\n\nVulnerability Type:\n\n\nExploit POC:</rich_text>\n \
            <rich_text>\n</rich_text>\n<rich_text weight="heavy">Description</rich_text>\n<rich_text>:\n\n\n\n</rich_text>\n \
            <rich_text underline="single" weight="heavy">Discovery of Vulnerability</rich_text>\n<rich_text>\n\n\n\n</rich_text>\n \
            <rich_text underline="single" weight="heavy">Exploit Code Used</rich_text>\n<rich_text>\n\n\n\n</rich_text>\n \
            <rich_text underline="single" weight="heavy">Proof\Local.txt File</rich_text>\n<rich_text>\n\n\n\n \
            ☐ Screenshot with ifconfig\ipconfig\n☐ Submit too OSCP Exam Panel\n\n\n</rich_text>\n</node>\n \
            <node name="Post Exploitation" unique_id="7" prog_lang="custom-colors" tags="" readonly="0" \
            custom_icon_id="21" is_bold="0" foreground="" ts_creation="0" ts_lastsave="1495714301">\n \
            <node name="Script Results" unique_id="4" prog_lang="custom-colors" tags="" readonly="0" \
            custom_icon_id="44" is_bold="0" foreground="" ts_creation="1495714301" ts_lastsave="1495714310"/>\n \
            <node name="Host Information" unique_id="15" prog_lang="custom-colors" tags="" readonly="0" \
            custom_icon_id="18" is_bold="0" foreground="" ts_creation="0" ts_lastsave="1500474204">\n \
            <rich_text underline="single" weight="heavy">Operating System</rich_text>\n<rich_text>\n\n\n</rich_text>\n \
            <rich_text underline="single" weight="heavy">Architecture</rich_text>\n<rich_text>\n\n\n</rich_text>\n \
            <rich_text underline="single" weight="heavy">Domain</rich_text>\n<rich_text>\n\n\n</rich_text>\n \
            <rich_text underline="single" weight="heavy">Installed Updates</rich_text>\n<rich_text>\n\n\n</rich_text>\n</node>\n \
            <node name="File System" unique_id="14" prog_lang="custom-colors" tags="" readonly="0" \
            custom_icon_id="18" is_bold="0" foreground="" ts_creation="0" ts_lastsave="1500474208">\n \
            <rich_text underline="single" weight="heavy">Writeable Files\Directories</rich_text>\n<rich_text>\n\n\n</rich_text>\n \
            <rich_text underline="single" weight="heavy">Directory List</rich_text>\n<rich_text>\n\n\n\n</rich_text>\n</node>\n \
            <node name="Running Processes" unique_id="8" prog_lang="custom-colors" tags="" readonly="0" \
            custom_icon_id="18" is_bold="0" foreground="" ts_creation="0" ts_lastsave="1495714268">\n \
            <rich_text underline="single" weight="heavy">Process List</rich_text>\n</node>\n \
            <node name="Installed Applications" unique_id="10" prog_lang="custom-colors" tags="" readonly="0" \
            custom_icon_id="18" is_bold="0" foreground="" ts_creation="0" ts_lastsave="1495714509">\n \
            <rich_text underline="single" weight="heavy">Installed Applications</rich_text>\n</node>\n \
            <node name="Users &amp; Groups" unique_id="11" prog_lang="custom-colors" tags="" \
            readonly="0" custom_icon_id="18" is_bold="0" foreground="" ts_creation="0" ts_lastsave="1500474213">\n \
            <rich_text underline="single" weight="heavy">Users</rich_text>\n<rich_text>\n\n\n</rich_text>\n \
            <rich_text underline="single" weight="heavy">Groups</rich_text>\n</node>\n \
            <node name="Network" unique_id="13" prog_lang="custom-colors" tags="" readonly="0" \
            custom_icon_id="18" is_bold="0" foreground="" ts_creation="0" ts_lastsave="1500474223">\n \
            <rich_text underline="single" weight="heavy">IPConfig\IFConfig</rich_text>\n<rich_text>\n\n\n</rich_text>\n \
            <rich_text underline="single" weight="heavy">Network Processes</rich_text>\n<rich_text>\n\n\n</rich_text>\n \
            <rich_text underline="single" weight="heavy">ARP</rich_text>\n<rich_text>\n\n\n\n</rich_text>\n \
            <rich_text underline="single" weight="heavy">DNS</rich_text>\n<rich_text>\n\n\n\n</rich_text>\n \
            <rich_text underline="single" weight="heavy">Route</rich_text>\n</node>\n \
            <node name="Scheduled Jobs" unique_id="16" prog_lang="custom-colors" tags="" readonly="0" \
            custom_icon_id="18" is_bold="0" foreground="" ts_creation="0" ts_lastsave="1496953428">\n \
            <rich_text underline="single" weight="heavy">Scheduled Tasks</rich_text>\n</node>\n</node>\n \
            <node name="Priv Escalation" unique_id="12" prog_lang="custom-colors" tags="" readonly="0" \
            custom_icon_id="10" is_bold="0" foreground="" ts_creation="0" ts_lastsave="1500474606">\n \
            <rich_text weight="heavy">Service Exploited:\n\n\nVulnerability Type:\n\n\nExploit POC:</rich_text>\n \
            <rich_text>\n\n</rich_text>\n<rich_text weight="heavy">Description</rich_text>\n<rich_text>:\n\n</rich_text>\n \
            <rich_text underline="single" weight="heavy">Discovery of Vulnerability</rich_text>\n<rich_text>\n\n\n\n</rich_text>\n \
            <rich_text underline="single" weight="heavy">Exploit Code Used</rich_text>\n<rich_text>\n\n\n\n</rich_text>\n \
            <rich_text underline="single" weight="heavy">Proof\Local.txt File</rich_text>\n<rich_text>\n \
            ☐ Screenshot with ifconfig\ipconfig\n☐ Submit too OSCP Exam Panel\n</rich_text>\n</node>\n \
            <node name="Goodies" unique_id="3" prog_lang="custom-colors" tags="" readonly="0" \
            custom_icon_id="43" is_bold="0" foreground="" ts_creation="0" ts_lastsave="1492949508">\n \
            <node name="Hashes" unique_id="9" prog_lang="custom-colors" tags="" readonly="0" custom_icon_id="18" \
            is_bold="0" foreground="" ts_creation="0" ts_lastsave="1492949998"/>\n \
            <node name="Passwords" unique_id="5" prog_lang="custom-colors" tags="" readonly="0" custom_icon_id="18" \
            is_bold="0" foreground="" ts_creation="0" ts_lastsave="1492950150"/>\n \
            <node name="Proof\Flags\Other" unique_id="6" prog_lang="custom-colors" tags="" readonly="0" \
            custom_icon_id="18" is_bold="0" foreground="" ts_creation="0" ts_lastsave="1496953479"/>\n</node>\n \
            <node name="Software Versions" unique_id="19" prog_lang="custom-colors" tags="" readonly="0" \
            custom_icon_id="12" is_bold="0" foreground="" ts_creation="0" ts_lastsave="1603476230">\n \
            <rich_text underline="single" weight="heavy">Software Versions</rich_text>\n<rich_text>\n\n\n\n</rich_text>\n \
            <rich_text underline="single" weight="heavy">Potential Exploits</rich_text>\n</node>\n \
            <node name="Methodology" unique_id="28" prog_lang="custom-colors" tags="" readonly="0" \
            custom_icon_id="13" is_bold="1" foreground="" ts_creation="1496953072" ts_lastsave="1500474082">\n \
            <rich_text underline="single" weight="heavy">Network Scanning</rich_text>\n<rich_text>\n\n \
            ☐  nmap -sn 10.11.1.*\n☐  nmap -sL 10.11.1.*\n☐  nbtscan -r 10.11.1.0/24\n☐  </rich_text>\n \
            <rich_text link="node 47">smbtree</rich_text>\n<rich_text>\n</rich_text>\n \
            <rich_text underline="single" weight="heavy">Individual Host Scanning</rich_text>\n \
            <rich_text>☐  nmap  --top-ports 20 --open -iL iplist.txt\n☐  nmap -sS -A -sV -O -p- ipaddress\n \
            ☐  nmap -sU ipaddress\n\n</rich_text>\n \
            <rich_text underline="single" weight="heavy">Service Scanning</rich_text>\n<rich_text>\n\n</rich_text>\n \
            <rich_text weight="heavy">WebApp</rich_text>\n<rich_text>☐   </rich_text>\n \
            <rich_text link="node 28">Nikto</rich_text>\n<rich_text>☐   </rich_text>\n \
            <rich_text link="node 32">dirb</rich_text>\n<rich_text>☐   dirbuster\n☐   </rich_text>\n \
            <rich_text link="node 30">wpscan</rich_text>\n<rich_text>☐   dotdotpwn\n☐   view source\n☐   davtest\cadevar \
            ☐   droopscan\n☐   joomscan\n☐   LFI\RFI Test\n</rich_text>\n \
            <rich_text weight="heavy">Linux\Windows</rich_text>\n<rich_text>☐   snmpwalk -c public -v1 </rich_text>\n \
            <rich_text style="italic">ipaddress</rich_text>\n<rich_text> 1\n☐   smbclient -L //ipaddress\n \
            ☐   showmount -e ipaddress port\n☐   rpcinfo\n☐   Enum4Linux\n</rich_text>\n \
            <rich_text weight="heavy">Anything Else</rich_text>\n<rich_text>☐   </rich_text>\n \
            <rich_text link="node 48">nmap scripts</rich_text>\n<rich_text> (locate *nse* | grep servicename)\n \
            ☐   </rich_text><rich_text link="node 35">hydra</rich_text>\n<rich_text>☐   MSF Aux Modules\n \
            ☐   Download the softward\n</rich_text>\n \
            <rich_text underline="single" weight="heavy">Exploitation</rich_text>\n<rich_text> \
            ☐   Gather Version Numbers\n☐   Searchsploit\n☐   Default Creds\n☐   Creds Previously Gathered\n \
            ☐   Download the software\n</rich_text>\n \
            <rich_text underline="single" weight="heavy">Post Exploitation</rich_text>\n<rich_text>\n</rich_text>\n \
            <rich_text weight="heavy">Linux</rich_text>\n<rich_text>☐   linux-local-enum.sh\n \
            ☐   linuxprivchecker.py\n☐   linux-exploit-suggestor.sh\n☐   unix-privesc-check.py\n</rich_text>\n \
            <rich_text weight="heavy">Windows</rich_text>\n<rich_text>☐   wpc.exe\n☐   windows-exploit-suggestor.py\n \
            ☐   </rich_text>\n<rich_text link="webs \
            https://github.com/pentestmonkey/windows-privesc-check/blob/master/windows_privesc_check.py">\n \
            windows_privesc_check.py</rich_text>\n<rich_text>☐  	windows-privesc-check2.exe\n</rich_text>\n \
            <rich_text underline="single" weight="heavy">Priv Escalation</rich_text>\n<rich_text>☐  </rich_text>\n \
            <rich_text link="node 36">acesss internal services (portfwd)</rich_text>\n<rich_text>☐  add account\n \
            </rich_text>\n<rich_text weight="heavy">Windows</rich_text>\n<rich_text>☐  List of exploits\n</rich_text>\n \
            <rich_text weight="heavy">Linux</rich_text>\n<rich_text>☐  sudo su\n☐  KernelDB\n☐  Searchsploit\n</rich_text>\n \
            <rich_text underline="single" weight="heavy">Final</rich_text>\n<rich_text> \
            ☐  Screenshot of IPConfig\WhoamI\n☐  Copy proof.txt\n☐  Dump hashes\n☐  Dump SSH Keys\n☐  Delete files</rich_text>\n \
            \n</node>\n<node name="Log Book" unique_id="1" prog_lang="custom-colors" tags="" readonly="0" \
            custom_icon_id="20" is_bold="1" foreground="" ts_creation="0" ts_lastsave="1495714168"/>\n</node>\n</cherrytree>'

            with open(filename, "w") as f:
                f.write(newCT)
                f.close()
            tree = ET.parse(filename)
            root = tree.getroot()
            display.indent(display(), root)
            tree.write(filename)
        
        else:
            tree = ET.parse(filename)
            root = tree.getroot()
            tcpnode = root.find('./node[@name="'+str(addy)+'"]/node[@name="Enumeration"]/node[@name="TCP"]')
            newscan = ET.SubElement(tcpnode, 'rich_text')
            newscan.text = data
            display.indent(display(), root)
            tree.write(filename)
        # print('Complete!')
        return

##########################################################################################

class _window(object):
    def __init__(self):
        self.screen = curses.initscr()
        self.height,self.width = self.screen.getmaxyx()
        self.height -= 1
        self.width -= 2
        self.pad = curses.newpad(500, self.width)
        self.pad.scrollok(True)
        self.pad.idlok(True)
        # self.pad.move(1, 1)
        self.mypad_pos = 0
        curses.noecho()
        curses.cbreak()
        curses.curs_set(0)
        self.screen.keypad(True)
        self.screen.nodelay(True)
        self.screen.border(0)
        # self.pad.border(0)
        curses.start_color()
        curses.init_pair(1, curses.COLOR_GREEN, curses.COLOR_BLACK)
        self.pad.bkgd(' ', curses.color_pair(1))
        self.screen.bkgd(' ', curses.color_pair(1))
        self.pad.refresh(0, 0, 1, 1, self.height, self.width)
    
    def kill(self):
        curses.nocbreak()
        self.screen.keypad(False)
        curses.echo()
        curses.endwin()

class display(object):
    def __init__(self, rootFile = 'scanio.xml'):
        self.rootfile = rootFile
        self.tsize = str(shutil.get_terminal_size((80, 20))).split(',')[0].split('=')[1]

    def progress(self, currcount, totalcount, seconds, progtext, net, window):
        totalscans = totalcount
        window = _window()
        # print(net)
        while currcount.value < totalscans:
            secs = seconds.value
            # tsize = str(shutil.get_terminal_size((80, 20))).split(',')[0].split('=')[1]
            progress = currcount.value / totalscans
            if float(secs) > 0:
                pps = currcount.value / float(secs)
                pps = "{:.0f}".format(pps)
            mon, sec = divmod(float(secs), 60)
            mon = "{:.0f}".format(mon)
            sec = "{:.0f}".format(sec)
            barLength = 20 # Modify this to change the length of the progress bar
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
            # printext = self.printall(net)
            update = "Percent: [{0}] {1}% {2} {3}/{4}. {5}m {6}s spent. ~{7} ports/s".format( "#"*block + "-"*(barLength-block), smallProgress, status, currcount.value, totalscans, mon, sec, pps)
            window.pad.addstr(1, 1, update)
            window.pad.refresh(window.mypad_pos, 0, 1, 1, window.height, window.width)
            time.sleep(0.05)
        progress = 1
        smallProgress = "{:.1f}".format(progress*100)
        update = "Percent: [{0}] {1}% {2} {3}/{4}. {5}m {6}s spent. ~{7} ports/s".format( "#"*block + "-"*(barLength-block), smallProgress, status, currcount.value, totalscans, mon, sec, pps)
        window.pad.addstr(1, 1, update)

    def indent(self, elem, level=0):
        i = "\n" + level*"  "
        if len(elem):
            if not elem.text or not elem.text.strip():
                elem.text = i + "  "
            if not elem.tail or not elem.tail.strip():
                elem.tail = i
            for elem in elem:
                self.indent(elem, level+1)
            if not elem.tail or not elem.tail.strip():
                elem.tail = i
        else:
            if level and (not elem.tail or not elem.tail.strip()):
                elem.tail = i
    
    def printall(self, addy):
        enumtext = ''
        printret = ''
        all_results = ''
        hlist = list()
        plist = list()
        try:
            
            if len(addy.split('.')) > 3:
                laddy = addy.split('.')
                naddy = '{0}.{1}.{2}'.format(laddy[0], laddy[1], laddy[2])
                ip = '{0}.{1}.{2}.{3}'.format(laddy[0], laddy[1], laddy[2], laddy[3])
                printret = ''
                tree = ET.parse(self.rootfile)
                root = tree.getroot()
                subnetstr = './subnet/[subnet-address = "'+naddy+'"]'
                subnet = root.find(subnetstr)
                subnethosts = subnet.findall('host')
                if subnethosts:
                    introptext = '\n---------------'

                    if ip == scanjobs.get_ip_address(scanjobs(), naddy):
                        introptext = '{0}\n{1} (current host)'.format(introptext, ip)
                    else:
                        introptext = '{0}\n{1}'.format(introptext, ip)

                    for p in root.findall('./subnet/[subnet-address = "'+naddy+'"]/host/[address = "'+ip+'"]/port/number'):
                        plist.append(int(p.text))

                    if plist:
                        # printret = '{0}'.format(' '*70)
                        printret = printret + introptext
                        hlist.append(ip)

                        for pp in sorted(plist):
                            spacelen = 5 - len(str(pp))
                            printtext = '\n|__ {0}'.format(pp)
                            # print('tsize = {0}'.format(int(tsize)))
                            endlen = int(self.tsize) - len(printtext)
                            pflag = 0
                            try:
                                for b in root.findall('./subnet/[subnet-address = "'+naddy+'"]/host/[address = "'+ip+'"]/port/[number = "'+str(pp)+'"]/banner'):
                                    if b.text:
                                        banner = b.text
                                        printtext = '\n|__ {0} {1}-> {2}'.format(pp, '-'*spacelen, banner[:50])
                                        pflag = 1
                                
                                for r in root.findall('./subnet/[subnet-address = "'+naddy+'"]/host/[address = "'+ip+'"]/port/[number = "'+str(pp)+'"]/robust'):
                                    if r.text:
                                        rb = r.text.splitlines()
                                        rb = '\n     '.join(rb)
                                        printtext = '\n|__ {0}'.format(rb)
                                        pflag = 1

                            except:
                                pass

                            if pflag == 0:
                                printtext = printtext

                            printret = '{0}{1}'.format(printret, printtext)         
                            plist.remove(pp)
                        
                    for g in root.findall('./subnet/[subnet-address = "'+naddy+'"]/host/[address = "'+ip+'"]/gobuster'):
                        if g.text:
                            enumtext = '{0}\n{1}'.format(enumtext, g.text)
                        else:
                            pass
                    
                    for vuln in root.findall('./subnet/[subnet-address = "'+naddy+'"]/host/[address = "'+ip+'"]/httpVuln'):
                        if vuln.text:
                            enumtext = '{0}\n{1}'.format(enumtext, vuln.text)
                        else:
                            pass
                        # printret = '{0}{1}'.format(printret, enumtext)
                all_results = '{0}{1}'.format(printret, enumtext)         
            else:
                naddy = addy
                tree = ET.parse(self.rootfile)
                root = tree.getroot()
                subnetstr = './subnet/[subnet-address = "'+naddy+'"]'
                subnet = root.find(subnetstr)
                subnethosts = subnet.findall('host')
                if subnethosts:
                    for h in root.findall('./subnet/[subnet-address = "'+naddy+'"]/host/address'):
                        hlist.append(h.text)
                    ip_list = [ip.strip() for ip in hlist]
                    for ip in sorted(ip_list, key = lambda ip: ( int(ip.split(".")[0]), int(ip.split(".")[1]), int(ip.split(".")[2]), int(ip.split(".")[3]))):
                        introptext = '\n---------------'
                        # printret = '{0}'.format(' '*70)
                        printret = printret + introptext
                        if ip == scanjobs.get_ip_address(scanjobs(), addy):
                            printret = '{0}\n{1} (current host)'.format(printret,ip)
                        else:
                            printret = '{0}\n{1}'.format(printret,ip)
                        for p in root.findall('./subnet/[subnet-address = "'+naddy+'"]/host/[address = "'+ip+'"]/port/number'):
                            plist.append(int(p.text))
                        for pp in sorted(plist):
                            spacelen = 5 - len(str(pp))
                            printtext = '\n|__ {0}'.format(pp)
                            # print('tsize = {0}'.format(int(tsize)))
                            endlen = int(self.tsize) - len(printtext)
                            pflag = 0
                            try:
                                for b in root.findall('./subnet/[subnet-address = "'+naddy+'"]/host/[address = "'+ip+'"]/port/[number = "'+str(pp)+'"]/banner'):
                                    if b.text:
                                        banner = b.text
                                        printtext = '\n|__ {0} {1}-> {2}'.format(pp, '-'*spacelen, banner[:50])
                                        pflag = 1
                                
                                for r in root.findall('./subnet/[subnet-address = "'+naddy+'"]/host/[address = "'+ip+'"]/port/[number = "'+str(pp)+'"]/robust'):
                                    if r.text:
                                        rb = r.text.splitlines()
                                        rb = '\n     '.join(rb)
                                        printtext = '\n|__ {0}'.format(rb)
                                        pflag = 1

                            except:
                                pass

                            if pflag == 0:
                                printtext = printtext

                            printret = '{0}{1}'.format(printret, printtext)         
                            plist.remove(pp)
                        
                        for g in root.findall('./subnet/[subnet-address = "'+naddy+'"]/host/[address = "'+ip+'"]/gobuster'):
                            if g.text:
                                enumtext = '{0}\n{1}'.format(enumtext, g.text)
                            else:
                                pass
                        
                        for vuln in root.findall('./subnet/[subnet-address = "'+naddy+'"]/host/[address = "'+ip+'"]/httpVuln'):
                            if vuln.text:
                                enumtext = '{0}\n{1}'.format(enumtext, vuln.text)
                            else:
                                pass
                        # printret = '{0}{1}'.format(printret, enumtext) 
                all_results = '{0}{1}'.format(printret, enumtext)
        except:
            pass
        return all_results, printret, enumtext, hlist



if __name__ == '__main__':
    scanjobs().start()
    
    
        

    