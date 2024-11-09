#!/bin/bash
################################################################################
# Written by: Ttime & previous MetroCCDC team member(s)
# For: Metro State CCDC 2024
# Purpose: To set appropriate firewall (iptables) rules for Linux hosts and
# add logging rules which may indicate a particular host is actively under
# attack.
################################################################################

# Define colors to improve readability of output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
RESET='\033[0m'

# Set default policies to DROP
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT DROP

# Flush all firewall rules
flushFirewall(){
  iptables -F
  iptables -X  # Remove all custom chains
  echo -e -n "${RED}"
  echo "Firewall rules removed, user beware!"
  echo -e "${RESET}"
}

# Drop all by default and only allow established traffic
dropAll(){
  iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  iptables --policy INPUT DROP
  iptables --policy FORWARD DROP
  iptables --policy OUTPUT DROP
}

# Log specific firewall events with rate limits
logFirewallEvents(){
  iptables -A INPUT -p tcp ! --syn -m state --state NEW -m limit --limit 1/min -j LOG --log-prefix "SYN packet flood: "
  iptables -A INPUT -p tcp ! --syn -m state --state NEW -j DROP
  iptables -A INPUT -f -m limit --limit 1/min -j LOG --log-prefix "Fragmented packet: "
  iptables -A INPUT -f -j DROP
  iptables -A INPUT -p tcp --tcp-flags ALL ALL -m limit --limit 1/min -j LOG --log-prefix "XMAS packet: "
  iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP
  iptables -A INPUT -p tcp --tcp-flags ALL NONE -m limit --limit 1/min -j LOG --log-prefix "NULL packet: "
  iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
  iptables -A INPUT -p icmp -m limit --limit 1/minute -j LOG --log-prefix "ICMP Flood: "
  iptables -A INPUT -p icmp -m limit --limit 3/sec -j ACCEPT
  iptables -A OUTPUT -p icmp -m limit --limit 3/sec -j ACCEPT
  iptables -A FORWARD -f -m limit --limit 1/min -j LOG --log-prefix "Hacked Client "
  iptables -A FORWARD -p tcp --dport 31337:31340 --sport 31337:31340 -j DROP
  iptables -A INPUT -i lo -j ACCEPT
  iptables -A OUTPUT -o lo -j ACCEPT
  iptables -A OUTPUT -m limit --limit 2/min -j LOG --log-prefix "Output-Dropped: " --log-level 4
  iptables -A INPUT -m limit --limit 2/min -j LOG --log-prefix "Input-Dropped: " --log-level 4
  iptables -A FORWARD -m limit --limit 2/min -j LOG --log-prefix "Forward-Dropped: " --log-level 4
}

# Display firewall rules
showFirewall(){
  echo -e -n "${GREEN}"
  echo -e "...DONE"
  echo -e -n "${CYAN}"
  iptables -L --line-numbers
  echo -e "${RESET}"
}

# Function to allow syslog traffic
allowSysLog(){
  iptables -A OUTPUT -p tcp --dport 9998 -j ACCEPT
  iptables -A OUTPUT -p tcp --dport 1516 -j ACCEPT
  iptables -A OUTPUT -p udp --dport 1514 -j ACCEPT
  iptables -A OUTPUT -p udp --dport 1515 -j ACCEPT
}

# Allow NTP traffic
allowNTP(){
  iptables -A INPUT -p udp --dport 123 -j ACCEPT
  iptables -A OUTPUT -p udp --dport 123 -j ACCEPT
}

# DNS and NTP setup
setDNS-NTP(){
  iptables -A INPUT -p tcp --dport 53 -j ACCEPT
  iptables -A INPUT -p tcp --dport 953 -j ACCEPT
  iptables -A INPUT -p udp --dport 53 -j ACCEPT
  iptables -A INPUT -p udp --dport 953 -j ACCEPT
  iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT
  iptables -A OUTPUT -p tcp --dport 953 -j ACCEPT
  iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
  iptables -A OUTPUT -p udp --dport 953 -j ACCEPT
  allowNTP
  allowSysLog
  dropAll
  showFirewall
}

# e-Commerce setup
setEcom(){
  iptables -A INPUT -p tcp --dport 80 -j ACCEPT
  iptables -A OUTPUT -p tcp --dport 80 -j ACCEPT
  iptables -A INPUT -p tcp --dport 443 -j ACCEPT
  iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT
  iptables -A OUTPUT -p udp --dport 123 -j ACCEPT
  allowSysLog
  dropAll
  showFirewall
}

# Webmail setup (Updated for HTTP, HTTPS, SMTP, POP3, and DNS)
setWebmail(){
  # HTTP and HTTPS for all
  iptables -A INPUT -p tcp --dport 80 -j ACCEPT    # Allow HTTP traffic
  iptables -A OUTPUT -p tcp --dport 80 -j ACCEPT   # Allow HTTP traffic
  iptables -A INPUT -p tcp --dport 443 -j ACCEPT   # Allow HTTPS traffic
  iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT  # Allow HTTPS traffic

  # SMTP for email
  iptables -A INPUT -p tcp --dport 25 -j ACCEPT    # Allow SMTP traffic
  iptables -A OUTPUT -p tcp --dport 25 -j ACCEPT   # Allow SMTP traffic

  # POP3 for webmail
  iptables -A INPUT -p tcp --dport 110 -j ACCEPT   # Allow POP3 traffic
  iptables -A OUTPUT -p tcp --dport 110 -j ACCEPT  # Allow POP3 traffic

  # DNS
  iptables -A INPUT -p tcp --dport 53 -j ACCEPT    # Allow DNS TCP traffic
  iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT   # Allow DNS TCP traffic
  iptables -A INPUT -p udp --dport 53 -j ACCEPT    # Allow DNS UDP traffic
  iptables -A OUTPUT -p udp --dport 53 -j ACCEPT   # Allow DNS UDP traffic

  allowSysLog
  dropAll
  showFirewall
}

# Palo workstation setup
setPaloWS(){
  flushFirewall

  # Allow loopback traffic
  iptables -A INPUT -i lo -j ACCEPT
  iptables -A OUTPUT -o lo -j ACCEPT

  # Splunk Web GUI port (Inbound and Outbound)
  iptables -A INPUT -p tcp --dport 8000 -d $2 -j ACCEPT       # Allow inbound access to Splunk Web GUI
  iptables -A OUTPUT -p tcp --sport 8000 -s $2 -j ACCEPT      # Allow outbound response to Splunk Web GUI

 # SSH (Inbound restricted to specific IP CHANGE THIS ASAP!!!)
 ALLOWED_SSH_IP="192.168.1.100"                               # Replace with your PC's IP
  iptables -A INPUT -p tcp -s $ALLOWED_SSH_IP --dport 22 -j ACCEPT  # Allow SSH only from specific IP
  iptables -A OUTPUT -p tcp --sport 22 -d $ALLOWED_SSH_IP -j ACCEPT # Allow outbound response to specific IP

  # DNS (Inbound and Outbound)
  iptables -A INPUT -p udp --sport 53 -m state --state ESTABLISHED -j ACCEPT   # Allow inbound DNS replies
  iptables -A INPUT -p tcp --sport 53 -m state --state ESTABLISHED -j ACCEPT   # Allow inbound DNS replies over TCP
  iptables -A OUTPUT -p tcp --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT  # Allow outbound DNS queries over TCP
  iptables -A OUTPUT -p udp --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT  # Allow outbound DNS queries over UDP

  # Web traffic (HTTP/HTTPS - Inbound and Outbound)
  iptables -A INPUT -p tcp --dport 80 -m state --state NEW,ESTABLISHED -j ACCEPT   # Allow inbound HTTP
  iptables -A INPUT -p tcp --dport 443 -m state --state NEW,ESTABLISHED -j ACCEPT  # Allow inbound HTTPS
  iptables -A OUTPUT -p tcp --dport 80 -m state --state NEW,ESTABLISHED -j ACCEPT  # Allow outbound HTTP
  iptables -A OUTPUT -p tcp --dport 443 -m state --state NEW,ESTABLISHED -j ACCEPT # Allow outbound HTTPS

  # NTP (Outbound only)
  iptables -A OUTPUT -p udp --dport 123 -d $3 -j ACCEPT        # Allow outbound NTP requests
  iptables -A INPUT -p udp --sport 123 -s $3 -j ACCEPT         # Allow inbound NTP replies

  # Splunk Syslog Ports (UDP 515 and TCP 601 - Inbound and Outbound)
  iptables -A OUTPUT -p udp --dport 515 -d $2 -j ACCEPT        # Allow outgoing syslog traffic to Splunk (UDP 515)
  iptables -A OUTPUT -p tcp --dport 601 -d $2 -j ACCEPT        # Allow outgoing syslog traffic to Splunk (TCP 601)
  iptables -A INPUT -p udp --sport 515 -s $2 -j ACCEPT         # Allow inbound syslog traffic from Splunk (UDP 515)
  iptables -A INPUT -p tcp --sport 601 -s $2 -j ACCEPT         # Allow inbound syslog traffic from Splunk (TCP 601)

  # ICMP (Ping - Inbound and Outbound for troubleshooting)
  iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT   # Allow inbound ping requests
  iptables -A OUTPUT -p icmp --icmp-type echo-reply -j ACCEPT    # Allow outbound ping responses
  iptables -A OUTPUT -p icmp --icmp-type echo-request -j ACCEPT  # Allow outbound ping requests
  iptables -A INPUT -p icmp --icmp-type echo-reply -j ACCEPT     # Allow inbound ping responses

  # Allow established/related incoming traffic for stateful connections
  iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
  iptables -A OUTPUT -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT

  # Logging and cleanup functions
  allowSysLog
  dropAll
  showFirewall
}

setSplunk(){
  flushFirewall

  # Allow loopback traffic
  iptables -A INPUT -i lo -j ACCEPT
  iptables -A OUTPUT -o lo -j ACCEPT

  # DNS
  iptables -A OUTPUT -p tcp --dport 53 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
  iptables -A OUTPUT -p udp --dport 53 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT 

  # Web traffic
  iptables -A OUTPUT -p tcp --dport 80 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
  iptables -A OUTPUT -p tcp --dport 443 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT

  # Splunk WebGUI rules 
  iptables -A INPUT -p tcp --dport 8000 -j ACCEPT
  iptables -A OUTPUT -p tcp --sport 8000 -j ACCEPT

  # Splunk Management Port
  iptables -A INPUT -p tcp --dport 8089 -j ACCEPT

  # Splunk Syslog Ports for Receiving Logs
  iptables -A INPUT -p udp --dport 515 -j ACCEPT   # Allow incoming syslog traffic over UDP on port 515
  iptables -A INPUT -p tcp --dport 601 -j ACCEPT   # Allow incoming syslog traffic over TCP on port 601

  # Splunk Syslog Ports for Sending Logs
  iptables -A OUTPUT -p udp --dport 515 -j ACCEPT   # Allow outgoing syslog traffic over UDP on port 515
  iptables -A OUTPUT -p tcp --dport 601 -j ACCEPT   # Allow outgoing syslog traffic over TCP on port 601

  allowSysLog
  dropAll
  showFirewall
}

# Call the function you want to apply
# Uncomment the function call you need

# setDNS-NTP       # For DNS and NTP setup
# setEcom          # For e-Commerce setup
# setWebmail       # For Webmail setup
# setPaloWS <SSH_IP> <Splunk_IP> <NTP_IP>   # For Palo workstation setup
# setSplunk        # For Splunk setup

# Example: Uncomment to activate Webmail setup by default
while getopts 'dewfpsha' OPTION; do
  case "$OPTION" in
    d)
      echo "Applying firewall rules for DNS-NTP..."
      setDNS-NTP
      ;;
    e)
      echo "Applying firewall rules for E-com..."
      setEcom
      ;;
    w)
      echo "Applying firewall rules for webmail..."
      setWebmail
      ;;
    p)
      echo "Applying firewall rules for Palo Workstation"
      read -p "Enter Palo IP address: " pip
      read -p "Enter SIEM/Splunk IP: " sip
      read -p "Enter DNS IP: " dip
      setPaloWS $pip $sip $dip
      ;;
    s)
      echo "Applying firewall rules for the Splunk machine"
      setSplunk
      ;;
    f)
      echo "Removing all firewall rules..."
      flushFirewall
      ;;
    a)
      echo "Applying all firewall configurations..."
      setDNS-NTP
      setEcom
      setWebmail
      # Provide IPs for PaloWS interactively or replace with static values
      read -p "Enter Palo IP address: " pip
      read -p "Enter SIEM/Splunk IP: " sip
      read -p "Enter DNS IP: " dip
      setPaloWS $pip $sip $dip
      setSplunk
      ;;
    h|?)
      echo -e -n "${YELLOW}"
      echo -e "Correct usage:\t $(basename $0) -flag(s)"
      echo -e "-d\t Applies firewall rules for DNS/NTP"
      echo -e "-e\t Applies firewall rules for E-com"
      echo -e "-w\t Applies firewall rules for Webmail"
      echo -e "-p\t Applies firewall rules for Palo (interactive input for IPs)"
      echo -e "-s\t Applies firewall rules for Splunk"
      echo -e "-f\t Deletes all firewall rules"
      echo -e "-a\t Applies all firewall rules in sequence"
      echo -e "-h\t Displays this help message."
      echo -e "${RESET}"
      exit 0
      ;;
  esac
done

# Check if no option was passed and display the help message
if [ $OPTIND -eq 1 ]; then
  echo -e -n "${YELLOW}"
  echo "No options were passed. Use -h for help."
  echo -e "${RESET}"
  exit 1
fi
