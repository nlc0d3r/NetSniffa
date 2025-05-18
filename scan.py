#!/usr/bin/env python3
import json
import nmap
import re
import os
import sys
import csv
import socket
import asyncio
from datetime import datetime
from scapy.all import ARP, Ether, srp

AppName     = "NetSniffa"
AppVersion  = "0.0.1alpha1"
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
def GetHostInfo( index, Host ):
    nm = nmap.PortScanner()
    ip = Host['ip']

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
        scan_result = nm.scan( ip, arguments='-sS -O -T4' )
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
        print(f"[!] Exception during Nmap scan of {ip}")

    results[index]['hostname'] = data['hostname']
    results[index]['vendor']   = GetMACVendors( Host['mac'] )
    results[index]['os']       = data['os']
    results[index]['ports']    = data['ports']
    # PrintData( results[index] )

async def AsyncGetHostInfo( index, Host ):
    if PyVersion() < 9:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor( None, GetHostInfo, index, Host )
    elif PyVersion() >= 9:
        return await asyncio.to_thread( GetHostInfo, index, Host )

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

# Nicely print the results
def PrintData( device ):
    print(f"[+] IP:          { Color( device['ip'], 'cyan' ) }")
    print(f" ├── Hostname:   {device['hostname']}")
    print(f" ├── MAC:        {device['mac']}")
    print(f" ├── Vendor:     {device['vendor']}")
    print(f" ├── OS:         {device['os']}")
    print(f" └── [+] Ports: ", end='')
    if device['ports']:
        for port in device['ports']:
            print(f"\n      ├── {port['port']} / {port['name']}", end='')
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

        print( f"{Color( '[+] Scanning:', 'cyan' ) }" )
        print( f"{Color( ' ├── Name:        '+ SubnetName, 'cyan' ) }" )
        print( f"{Color( ' └── Subnet:      '+ SubnetRange, 'cyan' ) }" )
        print( f"{Color( '[+] Scan Start:   '+ str(datetime.now()), 'cyan' ) }" )

        # 1st step scan ARP
        print( f"{Color( '[+] ARP Scan:', 'cyan' ) }" )
        GetARP( SubnetRange )
        if len( results ) > 0:
            print( f"{Color( ' ├── Hosts:       '+ str( len( results ) ), 'cyan' ) }" )
        else:
            print( f"{Color( ' ├── Hosts Found: None', 'cyan' ) }" )

        print( f"{Color( ' └── Done:        '+ str( datetime.now() - startTime ), 'cyan' ) }" )
        print( f"{Color( '~' * 100, 'cyan' ) }" )

        # Run GetHostInfo concurrently
        async def run_all():
            tasks = [AsyncGetHostInfo(index, Host) for index, Host in enumerate(results)]
            await asyncio.gather(*tasks)

            # Sort global results list by IP after tasks are done
            results.sort(key=lambda x: socket.inet_aton(x["ip"]))

            for device in results:
                PrintData(device)

        asyncio.run(run_all())

        # Calculate script execution time
        print( f"{Color( '[+] Scan is Done after '+ str( datetime.now() - startTime ), 'cyan' ) }" )

        # Create scans dir if not exist
        path = os.path.abspath(os.getcwd()) +"/scans"
        isExist = os.path.exists(path)
        if not isExist:
            os.makedirs( path )

        now = datetime.now()

        # Save data to CSV
        with open( path +"/"+ str( now.strftime("%Y-%m-%d_%H:%M") ) +"_"+ SubnetName +".csv", "w", newline="") as f:
            fieldnames = ['ip', 'mac', 'hostname', 'vendor', 'os', 'ports']
            w = csv.DictWriter( f, fieldnames=fieldnames )
            w.writeheader()

            for device in results:
                if device['ports']:
                    fld_ports = ''
                    for port in device['ports']:
                        fld_ports += f"{ str( port['port'] ) } { str( port['name'] ) } { str( port['state'] ) } { str( port['product'] ) }\n"
                else:
                    fld_ports = 'None'

                w.writerow({
                    'ip': device['ip'],
                    'mac': device['mac'],
                    'hostname': device['hostname'],
                    'vendor': device['vendor'],
                    'os': device['os'],
                    'ports': fld_ports.rstrip( '\n' ),
                })

        results.clear()

# Gets Python version
def PyVersion():
    FullVersion     = sys.version.split( ' ' )
    SplitVersion    = FullVersion[0].split( '.' )
    return int( SplitVersion[1] )

# Make header
def Header():
    Banner = r"""
 _   _      _   ____        _  __  __       
| \ | | ___| |_/ ___| _ __ (_)/ _|/ _| __ _ 
|  \| |/ _ \ __\___ \| '_ \| | |_| |_ / _` |
| |\  |  __/ |_ ___) | | | | |  _|  _| (_| |
|_| \_|\___|\__|____/|_| |_|_|_| |_|  \__,_|
    """
    print( f"{Color( Banner, 'cyan' ) }" )
    print( f"{Color( AppName +' v.'+ AppVersion, 'cyan' ) }" )
    print( f"{Color( AppAuthor, 'cyan' ) }" )
    print( f"{Color( AppRepo, 'cyan' ) }" )
    print( f"{Color( '=' * 100, 'cyan' ) }" )

def main():   
    try:
        # print header
        Header()

        # Read Subnet list from CSV file
        CSVScan()
   
    except KeyboardInterrupt:
        print( f"{Color( '[!] Script interrupted by user @ '+ str( datetime.now() ), 'red' ) }" )

if __name__ == '__main__':

    # Debug fixate script start time
    startTime = datetime.now()
    main()