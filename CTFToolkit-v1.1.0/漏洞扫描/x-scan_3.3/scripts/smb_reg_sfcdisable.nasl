#
# This script was written by Tenable Network Security
#
# This script is released under Tenable Plugins License
#

if(description)
{
 script_id(10449);
 script_version ("$Revision: 1.14 $");
 
 name["english"] = "SMB Registry : value of SFCDisable";
 
 script_name(english:name["english"]);
 
 desc["english"] = "

The registry key 
HKLM\SOFTWARE\Microsoft\Windows NT\WinLogon\SFCDisable
has its value set to 0xFFFFFF9D. 

This special value disables the Windows File Protection,
which allows any user on the remote host to view / modify
any file he wants.

This probably means that this host has been compromised.

Solution : set the value of this key to 0. You should reinstall
           this host

Reference : http://online.securityfocus.com/archive/1/66849
Reference : http://support.microsoft.com/default.aspx?scid=kb;en-us;Q222473

Risk factor : High
";


 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the value of SFCDisable";
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


key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon";
item = "SFCDisable";

key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if ( ! isnull(key_h) )
{
 value = RegQueryValue(handle:key_h, item:item);

 if (!isnull (value) && (value[1] != 0))
   security_hole(port);

 RegCloseKey (handle:key_h);
}

RegCloseKey (handle:hklm);
NetUseDel ();
