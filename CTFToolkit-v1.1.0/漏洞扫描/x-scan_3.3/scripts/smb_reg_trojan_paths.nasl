#
# This script was written by Tenable Network Security
#
# This script is released under Tenable Plugins License
#

if(description)
{
 script_id(10432);
 script_version ("$Revision: 1.21 $");
 script_cve_id("CAN-1999-0589");
 name["english"] = "SMB Registry : permissions of keys that can change common paths";
 
 script_name(english:name["english"]);
 
 desc["english"] = "

This script checks whether the following keys can
be modified by non admins :


HKLM\Software\Microsoft\Windows\CurrentVersion\App Paths
HKLM\Software\Microsoft\Windows\CurrentVersion\Controls Folder
HKLM\Software\Microsoft\Windows\CurrentVersion\DeleteFiles
HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer
HKLM\Software\Microsoft\Windows\CurrentVersion\Extensions
HKLM\Software\Microsoft\Windows\CurrentVersion\ExtShellViews
HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings
HKLM\Software\Microsoft\Windows\CurrentVersion\ModuleUsage
HKLM\Software\Microsoft\Windows\CurrentVersion\RenameFiles
HKLM\Software\Microsoft\Windows\CurrentVersion\Setup
HKLM\Software\Microsoft\Windows\CurrentVersion\SharedDLLs
HKLM\Software\Microsoft\Windows\CurrentVersion\Shell Extensions
HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Compatibility
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Drivers
HKLM\Software\Microsoft\Windows NT\CurrentVersion\drivers.desc
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Drivers32\0
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Embedding
HKLM\Software\Microsoft\Windows NT\CurrentVersion\MCI
HKLM\Software\Microsoft\Windows NT\CurrentVersion\MCI Extensions
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Ports
HKLM\Software\Microsoft\Windows NT\CurrentVersion\ProfileList
HKLM\Software\Microsoft\Windows NT\CurrentVersion\WOW

These keys contain paths to common programs and DLLs. If a user
can change a path, then he may put a trojan program
into another location (say C:/temp) and point to it.

Solution : use regedt32 and set the permissions of this
key to :

	- admin group  : Full Control
	- system       : Full Control
	- everyone     : Read
	
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the access rights of remote keys";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl", "smb_registry_access.nasl");
 script_require_keys("SMB/transport", "SMB/name", "SMB/login", "SMB/password", "SMB/registry_access");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_func.inc");

access = get_kb_item("SMB/registry_access");
if(!access)exit(0);

port = get_kb_item("SMB/transport");
if(!port)port = 139;

name	= kb_smb_name(); 	if(!name)exit(0);
login	= kb_smb_login(); 
pass	= kb_smb_password(); 	
domain  = kb_smb_domain(); 	
port	= kb_smb_transport();

if ( ! get_port_state(port) ) exit(0);
soc = open_sock_tcp(port);
if ( ! soc ) exit(0);

session_init(socket:soc, hostname:name);
r = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if ( r != 1 ) exit(0);

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if ( isnull(hklm) )
{
 NetUseDel();
 exit(0);
}

keys[0] = "Software\Microsoft\Windows\CurrentVersion\App Paths";
keys[1] = "Software\Microsoft\Windows\CurrentVersion\Controls Folder";
keys[2] = "Software\Microsoft\Windows\CurrentVersion\DeleteFiles";
keys[3] = "Software\Microsoft\Windows\CurrentVersion\Explorer";
keys[4] = "Software\Microsoft\Windows\CurrentVersion\Extensions";
keys[5] = "Software\Microsoft\Windows\CurrentVersion\ExtShellViews";
keys[6] = "Software\Microsoft\Windows\CurrentVersion\Internet Settings";
keys[7] = "Software\Microsoft\Windows\CurrentVersion\ModuleUsage";
keys[8] = "Software\Microsoft\Windows\CurrentVersion\RenameFiles";
keys[9] = "Software\Microsoft\Windows\CurrentVersion\Setup";
keys[10] = "Software\Microsoft\Windows\CurrentVersion\SharedDLLs";
keys[11] = "Software\Microsoft\Windows\CurrentVersion\Shell Extensions";
keys[12] = "Software\Microsoft\Windows\CurrentVersion\Uninstall";
keys[13] = "Software\Microsoft\Windows NT\CurrentVersion\Compatibility";
keys[14] = "Software\Microsoft\Windows NT\CurrentVersion\Drivers";
keys[15] = "Software\Microsoft\Windows NT\CurrentVersion\drivers.desc";
keys[16] = "Software\Microsoft\Windows NT\CurrentVersion\Drivers32\0";
keys[17] = "Software\Microsoft\Windows NT\CurrentVersion\Embedding";
keys[18] = "Software\Microsoft\Windows NT\CurrentVersion\MCI";
keys[19] = "Software\Microsoft\Windows NT\CurrentVersion\MCI Extensions";
keys[20] = "Software\Microsoft\Windows NT\CurrentVersion\Ports";
keys[21] = "Software\Microsoft\Windows NT\CurrentVersion\ProfileList";
keys[22] = "Software\Microsoft\Windows NT\CurrentVersion\WOW";

vuln = 0;
vuln_keys = "";

for(my_counter=0;keys[my_counter];my_counter=my_counter+1)
{
 key_h = RegOpenKey(handle:hklm, key:keys[my_counter], mode:MAXIMUM_ALLOWED | ACCESS_SYSTEM_SECURITY);
 
 if(!isnull(key_h))
 {
  rep = RegGetKeySecurity (handle:key_h, type: DACL_SECURITY_INFORMATION | SASL_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION);
  if(!isnull(rep) && registry_key_writeable_by_non_admin(security_descriptor:rep))
  {
   vuln_keys += '\nHKLM\\' + keys[my_counter];
   vuln = vuln + 1;
  }
  RegCloseKey (handle:key_h);
 }
}

RegCloseKey (handle:hklm);
NetUseDel();


if(vuln)
{
report = 
"The following registry keys are writeable by users who are not in 
the admin group : " 
+
 vuln_keys
+
string("\n") +

"These keys contain paths to common programs and DLLs. If a user
can change a path, then he may put a trojan program
into another location (say C:/temp) and point to it.


Solution : use regedt32 and set the permissions of this
key to :

	- admin group  : Full Control
	- system       : Full Control
	- everyone     : Read
	
Risk factor : High";

 security_hole(port:port, data:report);
}

