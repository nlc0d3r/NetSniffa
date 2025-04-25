# NetSniffa

## Installation

```bash
pip install -r /path/to/requirements.txt
```

## Usage

```bash
sudo python3 scan.py
```

## Input `subnets.csv` File Structure

```
<SUBNET_NAME>,<SUBNET_IP>
```

**Example:**
```
Office Network,192.168.0.1/24
Warehouse Network,192.168.0.1/24
```

## Action and Output Format

NetSniffa scans each subnet listed in `subnets.csv` to identify active hosts within the specified IP ranges. It uses ARP and NMAP requests to discover live devices.

### What it does:
- Parses each line in `subnets.csv`.
- Performs a network scan for the given subnet.
- Collects information such as IP address, MAC address, vendor name, hostname, OS and opened ports.
- Outputs the results into a timestamped CSV file.

### Example Output (CSV or terminal):

```
Subnet Name,IP Address,MAC Address,Hostname
Office Network,192.168.0.10,00:1A:2B:3C:4D:5E,workstation-10
Office Network,192.168.0.12,00:1A:2B:3C:4D:5F,printer-1
Warehouse Network,192.168.1.3,00:1A:2B:3C:4D:6A,scanner-2
```
