# netcup-api-ddns
A drop dead simple and lightweight Python3 client, that...
- uses Netcups DNS API to use a subdomain for DynDNS
- works with IPv4 and IPv6
- is based on nc_dnsapi from https://github.com/nbuchwitz/nc_dnsapi

## Prerequisites
- Python >= 3.11 with pip
- bash, git
- curl (for the default command to determine the external IPv4 / IPv6 addresses )

## Installation
- to install for development, run `setup_dev_venv.sh`
- to run: `setup_exec_venv.sh`

## Usage
- setup your credentials and configuration details in `netcup-ddns.conf`
- run `update_ddns_subdomain.py` in a venv with dependencies installed
   - the program can be stopped with kill / SIGTERM / SIGHUP or CTRL-C

## Notes / Remarks
- To disable IPv6, set the `fetch_ip6_cmd` configuration key to an empty value
- Make sure that the TTL in your netcup DNS zone is configured to a reasonable value, otherwise the new records won't be populated in acceptable time
- For quick testing, you could fetch the records directly from the netcup DNS: ```dig AAAA @root-dns.netcup.net subdomain.yourdomain.tld``` (omit AAAA for IPv4)
- For practical deployment on a Linux/Unix server or router, it is probably a good idea to: 
  - replace the curl commands to fetch external IPs with a local alternative that does not rely on remote machines to determine the external IPs
  - run this Python script with minimal privileges 
  - create a proper system service, e.g. systemd unit files on Linux