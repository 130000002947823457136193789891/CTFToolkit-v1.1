#
# (C) Tenable Network Security
#

if(description)
{
 script_id(12642);
 script_bugtraq_id(10681);
 script_version("$Revision: 1.8 $");

 name["english"] = "Mozilla/Firefox code execution";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is using Mozilla and/or Firefox, an alternative web browser.

The remote version of this software contains a weakness which may allow an
attacker to execute arbitrary programs on the remote host.

Solution : See http://mozilla.org/security/shell.html
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the version of Mozilla/Firefox";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}


include("smb_func.inc");

if ( ! get_kb_item("SMB/Registry/Enumerated") ) exit(1);


name	= kb_smb_name();
login	= kb_smb_login(); 
pass	= kb_smb_password(); 	
domain  = kb_smb_domain(); 	
port	= kb_smb_transport();

if ( ! get_port_state(port) ) exit(1);
soc = open_sock_tcp(port);
if ( ! soc ) exit(1);

session_init(socket:soc, hostname:name);
r = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if ( r != 1 ) exit(1);

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if ( isnull(hklm) ) 
{
 NetUseDel();
 exit(1);
}


key_h = RegOpenKey(handle:hklm, key:"SOFTWARE\mozilla.org\Mozilla", mode:MAXIMUM_ALLOWED);
if ( ! isnull(key_h) )
{
 item = RegQueryValue(handle:key_h, item:"CurrentVersion");
 if ( !isnull(item) )
 {
  moz = item[1];
  key_h2 = RegOpenKey(handle:hklm, key:"SOFTWARE\mozilla.org\Mozilla\" + moz + "\Main", mode:MAXIMUM_ALLOWED);
  if ( ! isnull(key_h2) )
  {
   path = RegQueryValue(handle:key_h2, item:"PathToExe");
   if ( ! isnull(path) ) 
   {
    set_kb_item(name:"Mozilla/Version", value:moz);
    if ( ereg(pattern:"^(0\.|1\.([0-6]\.|7\.0))", string:moz) ) 
    {
     flag = 1;
     security_hole(0);
    }
   }
   RegCloseKey(handle:key_h2);
  } 
 }
 RegCloseKey(handle:key_h);
} 


key_h = RegOpenKey(handle:hklm, key:"SOFTWARE\Mozilla\Mozilla FireFox", mode:MAXIMUM_ALLOWED);
if ( ! isnull(key_h) )
{
 item = RegQueryValue(handle:key_h, item:"CurrentVersion");
 if ( !isnull(item) )
 {
  fox = item[1];
  set_kb_item(name:"Mozilla/Firefox/Version", value:fox);
  if (ereg(pattern:"0\.([0-8]\.|9\.[01][^0-9])", string:fox) )
     {
     if ( ! flag ) security_hole(0);
     }
 }
 RegCloseKey(handle:key_h);
} 
else
{
 key_h = RegOpenKey(handle:hklm, key:"SOFTWARE\mozilla.org\Mozilla FireFox", mode:MAXIMUM_ALLOWED);
 if ( ! isnull(key_h) )
 {
  item = RegQueryValue(handle:key_h, item:"CurrentVersion");
  if ( !isnull(item) )
  {
  fox = item[1];
  set_kb_item(name:"Mozilla/Firefox/Version", value:fox);
  if (ereg(pattern:"0\.([0-8]\.|9\.[01][^0-9])", string:fox) )
     {
     if ( ! flag ) security_hole(0);
     }
  }
  RegCloseKey(handle:key_h);
 } 
}


key_h = RegOpenKey(handle:hklm, key:"SOFTWARE\Mozilla\Mozilla Thunderbird", mode:MAXIMUM_ALLOWED);
if ( ! isnull(key_h) )
{
 item = RegQueryValue(handle:key_h, item:"CurrentVersion");
 if ( !isnull(item) )
 {
  thunderbird = item[1];
  set_kb_item(name:"Mozilla/ThunderBird/Version", value:thunderbird);
 }
 RegCloseKey(handle:key_h);
} 


NetUseDel();
