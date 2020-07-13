#
# (C) Tenable Network Security
#
# Ref: 
# Date: Mon, 05 May 2003 16:44:47 -0300
# From: CORE Security Technologies Advisories <advisories@coresecurity.com>
# To: Bugtraq <bugtraq@securityfocus.com>,
# Subject: CORE-2003-0303: Multiple Vulnerabilities in Mirabilis ICQ client
#

if(description)
{
 script_id(11572);
 script_bugtraq_id(7461, 7462, 7463, 7464, 7465, 7466);
 script_version("$Revision: 1.5 $");
 script_cve_id("CAN-2003-0235", "CAN-2003-0236", "CAN-2003-0237", "CAN-2003-0238", "CAN-2003-0239");
 name["english"] = "Multiple ICQ Vulnerabilities";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is using ICQ - an instant messenging client utility.

There are multiple flaws in all versions of ICQ which may allow an attacker
to execute arbitrary code on this host.

To exploit this flaw, an attacker would need to send a malformed e-mail 
to the ICQ user, or have it download its mail on a rogue POP3 server.

Solution : None at this time
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Determines if ICQ is installed";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl","smb_registry_access.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password",
		     "SMB/domain","SMB/transport");

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

vuln = 0;

key = "SOFTWARE\Microsoft\CurrentVersion\Uninstall\ICQ";
item = "DisplayName";

key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if ( ! isnull(key_h) )
{
 value = RegQueryValue(handle:key_h, item:item);

 if (!isnull (value))
 {
   vuln = 1;
   security_note(port);
 }

 RegCloseKey (handle:key_h);
}


if (!vuln)
{
 key = "SOFTWARE\Microsoft\CurrentVersion\Uninstall\ICQLite";
 item = "DisplayName";

 key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
 if ( ! isnull(key_h) )
 {
  value = RegQueryValue(handle:key_h, item:item);

  if (!isnull (value))
  {
   vuln = 1;
   security_note(port);
  }

  RegCloseKey (handle:key_h);
 }
}


RegCloseKey (handle:hklm);
NetUseDel ();
