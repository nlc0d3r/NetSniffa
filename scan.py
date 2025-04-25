#!/usr/bin/env python3
import json
import nmap
import re
import csv
import socket
from datetime import datetime
from scapy.all import ARP, Ether, srp
from multiprocessing import Pool, cpu_count

AppName     = "NetSniffa"
AppVersion  = "0.01apha1"
AppAuthor   = "nlc0d3r"
AppRepo     = "https://github.com/nlc0d3r/NetSniffa"

SubnetListDict  = []
results         = []

with open( 'subnets.csv', "r", encoding="utf-8-sig", newline='' ) as CSVSubnets:
    SubnetList = csv.reader( CSVSubnets, delimiter=',', quotechar='|' )
    for row in SubnetList:
        SubnetListDict.append({
            'name':row[0],
            'subnet': row[1]
        })

# Load MAC vendors into a dict for fast lookup
with open( 'mac-vendors.json', 'r' ) as json_file:
    MacVendorList = { entry['macPrefix']: entry['vendorName'] for entry in json.load( json_file ) }

# Requires MAC and returns vendors
def GetMACVendors( Mac ):
    if Mac:
        Prefix = Mac[:8].upper()
        return MacVendorList.get(Prefix, "Unknown")
    return "Unknown"

# Get Current IP and Network Subnet
def GetIP():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout( 0 )
        try:
            # doesn't even have to be reachable
            s.connect( ( '10.254.254.254', 1 ) )
            IP = s.getsockname()[0]
        except Exception:
            IP = '127.0.0.1'
        finally:
            s.close()
        NET = re.sub( r'\b(\d+\.\d+\.\d+)\.\d+\b', r'\1.0', IP ) +"/24"
        return { "IP": IP, "NET": NET }

# Gets an advanced info about host
def GetHostInfo( ip ):
    nm = nmap.PortScanner()

    data = {
        'hostname': 'Unknown',
        'os': 'Unknown',
        'ports': [],
    }

    # Get hostname
    try:
        data['hostname'] = socket.gethostbyaddr( ip )[0]
    except socket.herror:
        pass

    try:
        # -sS -sU -p T:1-65535 --top-ports U:1000
        # -sS -sU -p T:1-65535 --top-ports U:1000 -O -T4 -Pn

        # -sS -p T:1-65535 -O
        # -sS -sU -p T:1-65535 U:1-1000 -O
        scan_result = nm.scan( ip, arguments='-sS -O -T4 -Pn' )
        if 'scan' in scan_result and ip in scan_result['scan']:
            host_info = scan_result['scan'][ip]

            # Open ports
            if 'tcp' in host_info:
                for port, port_data in host_info['tcp'].items():
                    if port_data['state'] == 'open':
                        data['ports'].append({
                            'port': port,
                            'name': port_data.get( 'name', '' ),
                            'state': port_data['state'],
                            'product': port_data.get( 'product', '' ),
                        })
            
            # OS detection
            if 'osmatch' in host_info and host_info['osmatch']:
                data['os'] = host_info['osmatch'][0]['name']
            else:
                data['os'] = 'Unknown' 
        else:
            print(f"[!] No Nmap scan result for {ip}")    
    except Exception as e:
        print(f"[!] Exception during Nmap scan of {ip}: {e}")

    return data

# Get ARP records
def GetARP( subnet ):
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=subnet), timeout=2, verbose=False)
    for sent, received in ans:
        data = {
            'ip': received.psrc,
            'mac': received.hwsrc
        }
        results.append( data )
    # Sort by the last octet
    results.sort( key=lambda x: int( x['ip'].split( '.' )[-1] ) )

def EnrichResults():
     for index, Host in enumerate( results ):
        info = GetHostInfo( Host['ip'] )
        results[index]['hostname'] = info['hostname']
        results[index]['vendor']   = GetMACVendors( Host['mac'] )
        results[index]['os']       = info['os']
        results[index]['ports']    = info['ports']
        PrintData( results[index] )

# Nicely print the results
def PrintData( device ):
    print(f"IP:        {device['ip']}")
    print(f"Hostname:  {device['hostname']}")
    print(f"MAC:       {device['mac']}")
    print(f"Vendor:    {device['vendor']}")
    print(f"OS Guess:  {device['os']}")
    print(f"[+] Open Ports: ", end='')
    if device['ports']:
        for port in device['ports']:
            print(f"\n |-- {port['port']}/{port['name']}", end='')
            # Also available: port['state'] port['product']
    else:
        print( 'None', end='')
    print( f"\n{Color( '~' * 100, 'cyan' ) }" )

# Let's Colorize CLI output
def Color( data, Color ):
    Colors = {
        "red":      "\033[91m",
        "green":    "\033[92m",
        "yellow":   "\033[93m",
        "blue":     "\033[94m",
        "magenta":  "\033[95m",
        "cyan":     "\033[96m"
    }
    ansi = Colors.get( Color, "\033[0m" )
    return ansi + data + "\033[0m"

def CSVScan():
    for item in SubnetListDict:
        SubnetName = item['name']
        SubnetRange = item['subnet']

        print( f"{Color( '[+] Scanning: '+ SubnetName +' with IP range: '+ SubnetRange +' @ '+ str(datetime.now()), 'cyan' ) }" )

        # 1st step scan ARP
        GetARP( SubnetRange )
        if len( results ) > 0:
            print( f"{Color( '[+] ARPScan has found: '+ str( len( results ) ) +' Hosts.', 'cyan' ) }" )
        else:
            print( f"{Color( '[+] There is no host found', 'cyan' ) }" )

        print( f"{Color( '[+] ARPScan is Done after '+ str( datetime.now() - startTime ), 'cyan' ) }" )
        print( f"{Color( '~' * 100, 'cyan' ) }" )

        EnrichResults()

        # Calculate script execution time
        print( f"{Color( '[+] Scan is Done after '+ str( datetime.now() - startTime ), 'cyan' ) }" )

        with open("scans/"+ SubnetName +"_"+ str( datetime.now() ) +".csv", "w", newline="") as f:
            w = csv.DictWriter(f, results.keys())
            w.writeheader()
            w.writerow(results)

        results.clear()

# Make header
def Header():
    Banner = r"""
         _  _  ____  ____  ___  _  _  ____  ____  ____  __   
        ( \( )( ___)(_  _)/ __)( \( )(_  _)( ___)( ___)/__\  
         )  (  )__)   )(  \__ \ )  (  _)(_  )__)  )__)/(__)\ 
        (_)\_)(____) (__) (___/(_)\_)(____)(__)  (__)(__)(__)
    """
    print( f"{Color( Banner, 'cyan' ) }" )
    print( f"{Color( AppName +' v.'+ AppVersion, 'cyan' ) }" )
    print( f"{Color( AppAuthor, 'cyan' ) }" )
    print( f"{Color( AppRepo, 'cyan' ) }" )
    print( f"{Color( '=' * 100, 'cyan' ) }" )

if __name__ == '__main__':
    try:
        # Debug fixate script start time
        startTime = datetime.now()

        # print header
        Header()

        # Read Subnet list from CSV file
        CSVScan()
   
    except KeyboardInterrupt:
        print( f"{Color( '[!] Script interrupted by user @ '+ str( datetime.now() ), 'red' ) }" )