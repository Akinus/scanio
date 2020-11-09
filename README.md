# scanio
Network recon and traversal tool suite

Network map depends on the [pyyed library](https://github.com/jamesscottbrown/pyyed).

To take advantage of the editable network map feature, use [yEd graph editor](https://www.yworks.com/products/yed).

***NOTE:***
===========
To correctly display the network map, go to 'layout-->One-Click Layout'.  Then you can go to 'tools-->Fit label to node'

usage: 
==========
scanio [-h] [-s START] [-e END] [-r RANGE] [-p PORTS] [-c] [-f] [--show] [-m] address

positional arguments:
=======================
  address               REQUIRED: This address will be a 3-octet or a 4-octet address.'

optional arguments:
======================
  -h, --help
  ----------------
  show this help message and exit
  
  -s START, --start START
  -----------------------
  Starting host number. The scan will begin at this host number. Defaults to 1
                          
  -e END, --end END
  -------------------------
  Ending host number. The scan will stop at this number if included Defaults to 254 ***If this option is enabled, you cannot use -r or --range.***
                          
  -r RANGE, --range RANGE
  ------------------------
  The range of hosts. This can be a comma separated list or a range ie: 1-30. This can also be a CIDR. ie: /27 - for 30 hosts. If a CIDR is used, the number of hosts will be added to the start. /30 = 2 hosts /29 = 6 hosts /28 = 14 hosts /27 = 30 hosts /26 = 62 hosts /25 = 126 hosts /24 = 254 hosts ***If this option is enabled, you cannot use -e or --end.***
                          
  -p PORTS, --ports PORTS
  ----------------------
  The ports to be scanned. Should be comma-separated or can be a range ie: 1-30. Defaults to list from: https://rb.gy/x86g6c
                          
  -c, --clearlog
  ------------------
  Clears the log and starts fresh.
  
  -f, --fast
  -----------------------
  Performs a fast scan using netcat vs the default /dev/tcp. This option does have the potential to miss some ports. REQUIRES NETCAT to be installed.
                          
  --show
  --------------------
  Shows the currently logged results for the address. When used with --map this will recreate the network map also
                          
  -m, --map
  ---------------------
  Creates a network map to a .graphml file Download yEd to edit scanio.graphml from https://www.yworks.com/products/yed

  -nC, --cnote 
  ---------------------
  Creates a new CherryTree note file with pre-determined template

  -nZ, --znote, 
  ---------------------
  Creates a new Zim folder structure and templated notes
    
  -pc, --proxychains
  ---------------------
  Changes the network saturation to try and avoid the too many files open

  -rb, --robust
  ---------------------
  Runs NMAP -A on found ports. WARNING: THIS WILL DRASTICALLY SLOW DOWN THE SCAN. ***REQUIRES NMAP TO BE INSTALLED***                                             

