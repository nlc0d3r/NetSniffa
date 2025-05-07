# NetSniffa

## Installation

Before you start installation process make sure to run update
```bash
sudo apt update
```

Install nmap on your machine
```bash
sudo apt install nmap -y
```

Install Pip
```bash
sudo apt install python3-pip -y
```

Go to directory where is located scan.py
```bash
cd /path/to/directory
```

Install required libraries needed for this scanner
```bash
sudo pip install -r /path/to/requirements.txt
```

## Preperation for scan 

After all is set up you need to create file `subnets.csv` where you will include the desired subnets you want to scan.

Create file `subnets.csv`
```bash
sudo nano subnets.csv
```

Add the desired subnets you want to scan.
```
<SUBNET_NAME>,<SUBNET_IP>
```

**Example:**
```
Office Network,192.168.0.1/24
Warehouse Network,192.168.0.1/24
```

Save and close the file.

## Usage

To run scanner use command below.
```bash
sudo python3 scan.py
```

## Action and Output Format

NetSniffa scans each subnet listed in `subnets.csv` to identify active hosts within the specified IP ranges. It uses ARP and NMAP requests to discover live devices.

### What it does:
- Parses each line in `subnets.csv`.
- Performs a network scan for the given subnet.
- Collects information such as IP address, MAC address, vendor name, hostname, OS and opened ports.
- Outputs the results into a timestamped CSV file.