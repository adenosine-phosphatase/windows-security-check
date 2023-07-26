# Check Zscaler service and tunnel status
# Check if ZScaler DLLs are signed and hash matches the precalculated hashes stored in separate text file
# Check windows defender services
# Check for any process running in debug mode
# Check for registry keys that start services upon system startup (explude known non-malicious keys)


import subprocess
import winreg
import hashlib
from signify.authenticode import SignedPEFile

# Check for ZScaler and Windows Defender services running status
def is_service_running(service_name):
   
    try:
        output = subprocess.check_output(['sc', 'query', service_name], universal_newlines=True)
        if 'STATE' in output and 'RUNNING' in output:
            return True
        else:
            return False
            
    except subprocess.CalledProcessError:
        return False

# Check the ZScaler tunnel status - this is not the same as service running status!
# Service can be running but with no tunnel established
def tunnel_state_check(key_path,value_name):
    try:
        # Open the registry key
       
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_READ)

        # Read the registry value
        value, value_type = winreg.QueryValueEx(key, value_name)

        # Close the registry key
        winreg.CloseKey(key)
        
        return value
        
    except FileNotFoundError:
        print(f"[-] Registry key not found: {key_path}")
        
    except WindowsError as e:
        print(f"[-] Error reading registry value: {str(e)}")

#Checking if there is any process running in the debug mode
def is_process_debugged(key_proc_path):
    try:
        key=winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_proc_path)
        value=winreg.QueryValueEx(key, "Debugger")
        winreg.CloseKey(key)
        return value
    
    except FileNotFoundError:
        print (f"[-] Registry key not found: {key_proc_path}")
        
    except WindowsError as e:
        print (f"[-] Error reading registry value: {str(e)}")
        
def calculate_file_hash(file_path):
    h=hashlib.sha256()
    
    with open(file_path, "rb") as file:
        chunk=0
        while chunk!=b'':
            chunk=file.read(1024)
            h.update(chunk)
    return h.hexdigest()
 
def any_startup_keys(startup_path):
    keys=[]
    process_harmless=True
    key_not_found=False
    
    ok_processes=["OneDrive", "Microsoft.Lists","com.squirrel.Teams.Teams", "MicrosoftEdgeAutoLaunch_E24627E95B553297751D71EEA548A773"]
    try:
        key=winreg.OpenKey(winreg.HKEY_CURRENT_USER, startup_path,0,winreg.KEY_READ)
        num_values=winreg.QueryInfoKey(key)[1]
              
        if num_values!=0:
        
            for i in range(num_values):
                process_name=winreg.EnumValue(key,i)
            
                if process_name[0] not in ok_processes:
            
                    print ("[+] Unknown process detected: ", process_name[0].split())
                    process_harmless=False
        
            if process_harmless==True:
                print ("[-] No malware detected in registry startup keys")
        else:
            print ("[-] No keys found in this section")
            process_harmless=True
        
        winreg.CloseKey(key)
        return process_harmless, None
    
    except Exception as e:
#   
        exception_id=type(e).__name__
        process_harmless=True
        return None,exception_id
       
        
if __name__ == '__main__':
    
    key_path = r"SOFTWARE\Zscaler\App"
    key_proc_path=r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
    startup_path=r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    startup_path2=r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
    startup_path3=r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run\services"
    startup_path4=r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\services"
    
    value_name = "ZPA_State"
    file_list=["ZSAAuth.dll","ZSALogger.dll","ZSATrayHelper.dll"]
    hash_file=[]
    
    zsa_tunnel_running = is_service_running('ZSATunnel')
    zsa_service_running = is_service_running('ZSAService')
   
    windef_running=is_service_running('Windefend')
    windef_atp=is_service_running('sense')
    windef_fw=is_service_running('mpssvc')
    windef_sec_center=is_service_running('wscsvc')
    windef_net_inspect=is_service_running('wdnissvc')
    
    print ("====Checking ZScaler=============")
    if zsa_tunnel_running:
        print("[+] ZSATunnel is running.")
    else:
        print("[-] ZSATunnel not running.")
    
    if zsa_service_running:
        print ("[+] ZSAService running...")
    else:
        print ("[-] ZSAService not running")
        
    tunnel_state = tunnel_state_check(key_path, value_name)
    
    if tunnel_state=="TUNNEL_FORWARDING":
        print ("[+] ZPA Tunnel authenticated")
    else:
        print ("[-] ZPA Tunnel in different state than expected(TUNNEL_FORWARDING)!")
       
    print ("====Checking Defender Services=======")
    
    if windef_running:
        print ("[+] Windows Defender AntiVirus Service is running")
    else:
        print ("[-] Windows Defender AntiVirus Service not running")
    
    if windef_atp:
        print ("[+] Windows Advance Threat Protection is running")
    else:
        print ("[-] Windows Advanced Threat Protection not running")
    
    if windef_fw:
        print ("[+] Windows Defender Firewall is running")
    else:
        print ("[-] Windows Defender Firewall not running")
        
    if windef_sec_center:
        print ("[+] Windows Security Center is running")
    else:
        print ("[-] Windows Security Center not running")
        
    if windef_net_inspect:
        print ("[+] Defender Antivirus Network Inspection Service is running")
    else:
        print ("[-] Defender Antivirus Network Inspection Service not running")
        
        
    print ("====Checking Signatures=======")
     
    for file in file_list:
    
        with open("C:\\Program Files (x86)\\Zscaler\\Common\\lib\\" + file, "rb") as f:
            pefile=SignedPEFile(f)
                                   
            if pefile:
                print ("[+] %s signed" % file)
            else:
                print ("[-] %s not signed" % file)

            hash_file=str(calculate_file_hash(str("C:\\Program Files (x86)\\Zscaler\\Common\\lib\\" + file)))
            
            with open('C:\\Users\\WZHIVSA\\docs\\Experiments\\python\\zscaler-file-hashes.txt', 'r') as file_hashes:
#
                for line in file_hashes:
                    data=line.split()
                    
#                    print (file+"=>"+hash_file+"=>"+data[1]+"=>"+data[0])   
#                   This is critical - you need to ensure the filename from the file equals the name of the file from the loop and that calculated hash matches the
#                   hash contained in the file
 
                    if str(data[1])==hash_file and data[0]==file:
                        print ("[+] The file has not been changed", file)
                    elif str(data[1])!=hash_file and data[0]==file:
                        print ("[!] The file has different checksum:", file) 
       
                            
#            print ("[+] %s has hash of: " % file, hash_file)
            
    print ("====Checking for any process being debugged===")
    
    is_debugged=is_process_debugged(key_proc_path)
    
    if is_debugged:
        print ("[+] Debugger running!!")
    else:
        print ("[-] No debugger running")
        
    
    print ("====Checking for Run startup registry keys===")
    process_harmless,exception_id=any_startup_keys(startup_path)

    print ("====Checking for RunOnce startup registry keys===")
    process_harmless,exception_id=any_startup_keys(startup_path2)
  
    print ("====Checking for Run Services startup registry keys===")
    process_harmless,exception_id=any_startup_keys(startup_path3)
    
    if exception_id:
        print("[-] No keys found in this section")
   
    print ("====Checking for RunOnce Services startup registry keys===")
    process_harmless=any_startup_keys(startup_path4)
  
    if exception_id:
        print("[-] No keys found in this section")
      
      
      
       