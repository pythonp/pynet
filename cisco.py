################### All in one Application for Extracting Network parameters: Cisco
################### Running-configuration, ARP table, MAC table, MAC to IP mapping,
################### Route Table, Dynmaic Routing Protocol, Routing Protocol Neighbors,
################### Interface status, VLAN port assignments, CDP Neighbors, 
################### Interface Utilization, Device Inventory. "Still under Development and testing".
                                                         

# Configure the permissions on the script first ! 'chmod 755 NetInv.py'
# Ensure SSHV2 is enabled on devices with 1024 bit key
# Telnet will be used if SSHV2 is not available on Devices
# Standard TACACS accounts will be used for LAN, WAN devices. Other Credentials will be attempted if standard Tacacs fails

###############Application Part 1#################

import paramiko
import threading
import os.path
import subprocess
import datetime
import time
import sys
import re



# Write network Data captured from devices to disk. 
def write_data(hostname, netdata, command):
    try:
        home_dir = os.path.join('/home','a0694441', 'Cisco')
        os.chdir(home_dir)
        device_dir = os.path.join (hostname,datetime.datetime.now().strftime('%Y-%m-%d'))
        
        if os.path.exists(device_dir)==False:
            os.makedirs(device_dir)
        
        os.chdir(device_dir)
        
        #filename = command + "-" + datetime.datetime.now().strftime('%Y-%m-%d')
        filename = command
        net_file = open (filename, "w")
        net_file.seek(0)
        net_file.write (netdata)
        net_file.close()
        
    except OSError,e:
        print "Could not create directory in path %s or Directory exists" %home_dir
        
    except IOError:
            print "\n *Couldnt write to file %s !" %net_file
            sys.exit()
            
# Module for output coloring
from colorama import init, deinit, Fore, Style

#Initialize Colorama
init()

global ip_file
global user_file

# Checking the number of arguments passed to the script
if len(sys.argv)==3:
    ip_file = sys.argv[1]
    user_file=sys.argv[2]
    print Fore.BLUE + Style.BRIGHT + "\n\n* The script will be executed using files:\n"
    print Fore.BLUE + "Cisco Network IP file is:" + Fore.YELLOW + "%s" % ip_file
    print Fore.BLUE + "SSHV2 Connection file is:" + Fore.YELLOW + "%s" % user_file
        
else:
    print Fore.RED + Style.BRIGHT + "\nIncorrect number of arguments (files) passed into  the Script. \
    Please ensure 'Device IP list, Credentials parameters are passed"
    print Fore.RED + "\n Please try again with correct number of parameters"
    sys.exit()
    
    
#Checking IP address file and content validity
def ip_is_valid():
    check = False
    global ip_list
    
    while True:
        #Changing Exception message
        try:
            #Open user selected file for reading (IP address file)
            selected_ip_file = open(ip_file,'r')
            
            #Starting from the begning of the file
            selected_ip_file.seek(0)
            
            #Reading each line (IP address in the file)
            ip_list = selected_ip_file.readlines()
            
            #closing the file
            selected_ip_file.close()
        
        except IOError:
            print Fore.RED + "\n *File %s doesnt exist!  Please check and try again" %ip_file
            sys.exit()
            
        #Checking Octects
        
        for ip in ip_list:
            a= ip.split('.')
            
            if(len(a)==4) and (1<=int(a[0])<=223) and (int(a[0])!=127) and (int(a[0])!=169 or int(a[1])!=
            254) and (0<=int(a[1])<=255 and 0<=int(a[2])<=255 and 0<=int(a[3])<=255):             
                check = True                         
                #print ip
            else:
                print "\n*There was an INVALID IP address! Please check and try again!\n"
                check = False
                continue
            
        if check == False:
            sys.exit()
                        
        elif check == True:
            break

    #Checking IP Reachability
    print   "**Checking IP reachability....  Please wait ..."
    
    Check2 = False
    
    while True:
            for ip in ip_list:
                ping_reply = subprocess.call(['ping', '-c', '3', '-w', '3' ,'-q' , '-n' , ip], stdout = subprocess.PIPE)
                if ping_reply == 0:
                    check2 = True
                    continue
                elif ping_reply == 2:
                    print Fore.RED + "\n No response from device %s ."  %ip
                    check2 = False
                    break
                else:
                    print Fore.RED + "\nPing to the following device has failed:",ip
                    check2 = False
                    break
                
            #Evaluating the Check Flag
            
            if check2 == False:
                print Fore.RED + "*Please recheck IP address list or device list.\n"
                sys.exit()
            elif check==True:
                print "\n* All devices are reachable. Checking SSHV2 connection file....\n"
                break    
                    
                
#Checking User File validity
def user_is_valid():
    global user_file
    
    while True:
        #Changing Output messages
        if os.path.isfile(user_file) == True:
                print "\n SSHV2 file has been validated !\n"
                break
        else:
                print Fore.RED + "\n File %s doesnt exist. Please check and try again\n" %user_file
                sys.exit()

#Change Exception message
try:
    #Calling IP file validity function
    ip_is_valid()
    
except KeyboardInterrupt:
    print Fore.RED + "\n\nProgram aborted by the user.Exiting...\n"
    sys.exit()
    
#Change Exception message
try:
    #Calling User file validity function
    user_is_valid()
    
except KeyboardInterrupt:
    print Fore.RED + "\n\n Program aborted by the user.Exiting...\n"
    sys.exit()
    
##############Application part#2  ####################

    #Initialize necessary lists , strings and dictionaries
    
    show_run = ""
    show_arp = ""
    show_mac = ""
    show_route = ""
    show_protocols = ""
    show_vlan = ""
    show_int_status = ""
    show_cdp_detail = ""
    show_inv = ""
    show_diag = ""
    show_int_statistics = ""
    show_version = ""
    show_flash = ""
    cpu_values =[]
    io_mem_values = []
    proc_mem_values =[]
    upint_values=[]
    top3_cpu ={}
    top3_io_mem={}
    top3_proc_mem ={}
    

#Open SSHV2 connection to the devices
def open_ssh_conn(ip,hostname,sshport,output):
    #Change Exception message
    #print "inside ssh call function\n"
    print ip,hostname,sshport
    try:
        #Define SSH parameters
        user_file_temp = '/home/debian/workingdir/' + user_file
        selected_user_file = open(user_file_temp, 'r')
        #print "open file success"
        #Start from the begning of the file
        selected_user_file.seek(0)
        
        #Reading username from the file
        username = selected_user_file.readlines()[0].split(',')[0]
        
        #Starting from begning of the file
        selected_user_file.seek(0)
        
        
        password = selected_user_file.readlines()[0].split(',')[1].rstrip("\n")
         
        #print username
        #print password
        #Logging into the device
        session = paramiko.SSHClient()
        #print  "First invoke"
        #For testing purposes , this allows accepting of unknow host keys , DO NOT use in production!
        #The default would be reject policy
        
        session.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        #print "Policy  success"
        #Connect to the device using username and password
        
        session.connect (ip,username = username, password = password)
        
        #Start an interactive shell session on the router
        connection = session.invoke_shell()
        print "Shell Success:" + ip
        #Setting terminal Length for entire output - disable pagination
        connection.send("terminal length 0 \n")
        connection.recv(1024)     
        #time.sleep(1)
        
        #Reading commands from within the script
        #Using the "\" line continuation character for better readability of commands to be sent
        
        selected_cisco_commands = '''show version | include (, Version|uptime is|bytes of memory|Hz)&\
show inventory&\
show interfaces | include bia&\
show processes cpu | include CPU utilization&\
show memory statistics&\
show ip int brief | include (Ethernet|Serial)&\
show cdp neighbor detail | incl Device ID&\
show ip protocols | include Routing Protocol&\
show runn &\
show ip arp &\
show mac-address-table &\
show mac address-table&\
show vlan brief &\
show ip bgp summ &\
show ip bgp &\
show ip route &\
show ip ospf database &\
show ip ospf interface &\
show ip ospf nei'''
        
        #Splitting the commands by '&' charecter
        command_list = selected_cisco_commands.split("&")
        #print len(command_list)
        #print command_list
        
        #Writing each line in the command string to the device
        #print output
        
        for count_commands in range (0,len(command_list)):
            file_to_write=""
            #print  command_list[count_commands]
            data_to_read = True
            connection.send(command_list[count_commands] +"\n")
            time.sleep(4)
            #connection.recv(5000)
            #print each_line
            file_to_write_list = command_list[count_commands].split("|")
            file_to_write = file_to_write_list[0].replace(" ","")
            file_to_write = file_to_write.replace("show","show-")
            data_to_write  = ""
            
            while data_to_read:
                if connection.recv_ready():
                    data_to_write+= data_to_write + connection.recv(5000)
                    #print data_to_write
                    
                else:
                    data_to_read = False
            output+= data_to_write
            write_data(hostname, data_to_write, file_to_write)
            
            
            
        
        
        #Closing the user file
        selected_user_file.close()
        
        
        #output = connection.recv(65535)
                
        #Checking command output for IOS syntax errors 
        if re.search(r"% Invalid input detected at", output):        
            print Fore.RED + "* There was atleast one IOS syntax error on devices %s" %ip
            
        else:
            print Fore.GREEN + "* All Parameters were successfully extracted from the device %s" %ip
            
        #Test for reading command output
        #print output + "\n"
        


################# Application Part##########3

        #Extracting Device Parameters

        dev_hostname = re.search(r"(.+) uptime is", output)
        hostname = dev_hostname.group(1)
        #print hostname
        #write_data(hostname,output,"show-run")
        
        dev_mac = re.findall(r"\(bia(.+?)\)",output)
        mac =   dev_mac[0]
        #print mac
        dev_vendor=re.search(r"(.+?) (.+) bytes of memory", output)
        vendor = dev_vendor.group(1)
        #print vendor
        
        dev_model = re.search(r"(.+?) (.+?) (.+) bytes of memory", output)
        model = dev_model.group(2)
        #print model
                
        dev_image_name = re.search(r" \((.+)\), Version", output)
        image_name = dev_image_name.group(1) 
        #print image_name 
         
        dev_os = re.search(r'\), Version (.+),', output) 
        os = dev_os.group(1) 
        #print os
        
        serial_no =""
        if len(re.findall(r"(.+), SN: (.+?)\r\n", output))==0:
            serail_no="unknown"
        else:
            serial_no=re.findall(r"(.+), SN: (.+?)\r\n", output)[0][1].strip()
            #print re.findall(r"(.+), SN: (.+?)\r\n", output)[0]
            
        #print serial_no
        
        dev_uptime=re.search(r"uptime is (.+)\n", output)
        uptime = dev_uptime.group(1)
        uptime_value_list=uptime.split(',')
        #print uptime_value_list
        #Getting device up time in seconds
        
        y_sec=0
        w_sec=0
        d_sec=0
        h_sec=0
        m_sec=0
        
        for j in uptime_value_list:
            if 'year' in j:
                y_sec = int(j.split(' ')[0]) * 31449600
                
            elif 'week' in j:
                w_sec=int(j.split(' ')[0])* 604800
            
            elif 'day' in j:
                d_sec = int(j.split(' ')[0]) * 8600
                
            elif 'hour' in j:
                h_sec = int(j.split(' ')[0]) * 3600
            
            elif 'minute' in j:
                m_sec = int(j.split(' ')[1]) * 60
                #print m_sec
                
        total_uptime_sec = y_sec+ w_sec+ d_sec + h_sec + m_sec
        #print total_uptime_sec
        
        cpu_model=""
      
          
        if re.search(r".isco (.+?) \((.+)\) processor(.+)\n", output) == None: 
            cpu_model = "unknown"
        else:
            cpu_model = re.search(r".isco(.+?)\((.+)\) processor(.+)\n",output).group(2)
        #print cpu_model
        
        cpu_speed=""
        
        if re.search(r" (.+?)at (.+?)MHz(.+)\n", output) == None:
            cpu_speed = "unknown"
        else:
            cpu_speed = re.search(r" (.+?)at(.+?)MHz(.+)\n",output).group(2)
        #print cpu_speed
        
        serial_int = ""
        
        if re.findall(r"Serial([0-9]*)/([0-9]*)(.+)\n", output) == None:
            serial_int="No Serial"
        else:
            serial_int = len(re.findall(r"Serial([0-9]*)/([0-9]*)(.+)\n", output))
        #print serial_int
       
        dev_cdp_neighbors  = re.findall(r"Device ID: (.+)\r\n", output)
        
        all_cdp_neighbors = ','.join(dev_cdp_neighbors)
        #print all_cdp_neighbors
        
        dev_routing_pro = re.findall(r"Routing Protocol is \"(.+)\"\r\n", output)
        #print dev_routing_pro
        
        is_internal=[]
        is_external=[]
        
        for protocol in dev_routing_pro:
            if 'bgp' in protocol:
                is_external.append(protocol)
            else:
                is_internal.append(protocol)
        
        internal_pro = ','.join(is_internal)
        external_pro= ','.join(is_external)
        
        #print internal_pro
        #print external_pro
        
          
    except re.error,e:
        print e.arg[0],e.arg[1]
        
       

    
# Test application
#global output
#global hostname
#hostname = "R1"
#netdata = "show run"
#command_output = "show-run"
#output = ""
#open_ssh_conn("192.168.2.101",output,hostname,sshport)

#Main Program to collect network information, references previously defined functions.

#Read devices.csv file and get details of devices to connect to for gatehring network infomration
#Changing Exception message
try:
    #Open Devices selected file for reading (IP address , SSH port , Hostname)
    selected_devices_file = open('devices.csv','r')
            
    #Starting from the begning of the file
    selected_devices_file.seek(0)
          
    #Reading each line (IP address, SSH port and Hostname in the file)
    global device_list
    device_list = selected_devices_file.readlines()
           
    #closing the file
    selected_devices_file.close()
                
except IOError:
        print Fore.RED + "\n *File %s doesnt exist!  Please check and try again" %selected_devices_file

# Connect to devices in the list and gather network infomration
for devices in device_list:
    global output
    global ip
    global hostname
    global sshport
    
    ip = devices.split(",")[0]
    hostname = devices.split(",")[1]
    sshport = devices.split(",")[2]
    output = ""
    #print ip,hostname,sshport
    print "\nGathering data from %s. Please be patient......" %hostname
    open_ssh_conn(ip,hostname,sshport,output)

            
