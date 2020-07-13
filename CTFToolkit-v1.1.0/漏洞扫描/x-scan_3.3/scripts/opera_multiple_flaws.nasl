#
# (C) Tenable Network Security
#

if(description)
{
 script_id(11404);
 script_bugtraq_id(6218, 6754, 6755, 6756, 6757, 6759, 6811, 6814, 6962, 7056);
 
 script_version("$Revision: 1.7 $");

 name["english"] = "Multiple flaws in the Opera web browser";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is using Opera - an alternative web browser.

The version installed is vulnerable to various security flaws, ranging
from cross site scripting to buffer overflows.

To exploit them, an attacker would need to set up a rogue web site, then
lure a user of this host visit it using Opera. He would then be able
to execute arbitrary code on this host.

Solution : Install Opera 7.0.3 or newer
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the version of Opera.exe";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}


include("smb_func.inc");

if ( ! get_kb_item("SMB/Registry/Enumerated") ) exit(0);




name 	=  kb_smb_name();
login	=  kb_smb_login();
pass  	=  kb_smb_password();
domain 	=  kb_smb_domain();
port    =  kb_smb_transport();
if(!get_port_state(port))exit(1);

soc = open_sock_tcp(port);
if(!soc)exit(1);

session_init(socket:soc, hostname:name);
r = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if ( r != 1 )  exit(1);


hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if ( isnull(hklm) )
{
 NetUseDel();
 exit(1);
}

key_h = RegOpenKey(handle:hklm, key:"SOFTWARE\Netscape\Netscape Navigator\5.0, Opera\Main", mode:MAXIMUM_ALLOWED);
if ( isnull(key_h) )
{
 RegCloseKey(handle:hklm);
 NetUseDel();
 exit(0);
}

value = RegQueryValue(handle:key_h, item:"Install Directory");
RegCloseKey(handle:key_h);
NetUseDel(close:FALSE);

if ( isnull(value) ) exit(0);
rootfile = value[1];
share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:rootfile);
file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1\Opera.exe", string:rootfile);


r = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if ( r != 1 )
{
 NetUseDel();
 exit(1);
}


handle = CreateFile (file:file, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL,
                     share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);
if( isnull(handle) )
{
 NetUseDel();
 exit(0);
}

fsize = GetFileSize(handle:handle);
off = fsize - 90000;

while(fsize != off)
{
 data = ReadFile(handle:handle, length:16384, offset:off);
 data = str_replace(find:raw_string(0), replace:"", string:data);
 version = strstr(data, "ProductVersion");
 if(!version)off += 16383;
 else break;
}


CloseFile(handle:handle);
NetUseDel();
if ( ! version ) exit(1);

for(i=strlen("ProductVersion");i<strlen(version);i++)
{
 if((ord(version[i]) < ord("0") ||
    ord(version[i]) > ord("9")) && 
    version[i] != ".")break;
 else 
   v += version[i];
}


if(strlen(v))
{
  report = "
We have determined that you are running Opera v." + v + ". This version
is vulnerable to various security flaws which may allow an attacker to
execute arbitrary code on this host. 

To exploit these flaws, an attacker would need to set up a rogue website
and lure a user of this host visit it using Opera. He would then be able
to execute arbitrary code on this host.

Solution : Upgrade to version 7.03 or newer
Risk factor : High";

  set_kb_item(name:"Host/Windows/Opera/Version", value:v);
  v2 = split(v, sep:".", keep:FALSE);

  if(int(v2[0]) < 7 || (int(v2[0]) == 7 && int(v2[1]) < 3))security_hole(port:port, data:report);
}
