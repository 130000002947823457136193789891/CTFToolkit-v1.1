#
# (C) Tenable Network Security
#

if(description)
{
 script_id(16333);
 script_version("$Revision: 1.3 $");
 script_cve_id("CAN-2004-0847");
 script_bugtraq_id(11342);
 name["english"] = "ASP.NET Path Validation Vulnerability (887219)";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running a version of the ASP.NET framework which contains
a flaw which may allow an attacker to bypass the security of an ASP.NET website
and obtain unauthorized access.

Solution : http://www.microsoft.com/technet/security/bulletin/ms05-004.mspx
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the version of the ASP.Net DLLs";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/WindowsVersion");
 script_require_ports(139, 445);
 exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");
rootfile = hotfix_get_systemroot();
if(!rootfile) exit(0);

share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:rootfile);
dll =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1\Microsoft.Net\Framework\v1.1.4322\System.web.dll", string:rootfile);
dll2 =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1\Microsoft.Net\Framework\v1.0.3705\System.web.dll", string:rootfile);





name 	=  kb_smb_name();
login	=  kb_smb_login();
pass  	=  kb_smb_password();
domain 	=  kb_smb_domain();
port    =  kb_smb_transport();

if(!get_port_state(port))exit(1);

soc = open_sock_tcp(port);
if(!soc)exit(1);

session_init(socket:soc, hostname:name);
r = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if ( r != 1 ) exit(1);


try2 = 0;
handle =  CreateFile (file:dll, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL, share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING); 

if ( isnull(handle) )
{
 try2 = 1;
 handle =  CreateFile (file:dll2, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL, share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING); 
}

	
if( ! isnull(handle) )
{
 v = GetFileVersion(handle:handle);
 CloseFile(handle:handle);
 if ( ! isnull(v) ) 
 {
 # < 1.1.4322.2037  -> vulnerable
 # < 1.0.3705.6021  -> vulnerable (1.0 SP3)
 # < 1.0.3705.556 -> vulnerable (1.0 SP2)
 if ( ( try2 == 0 && v[0] == 1 &&  v[1] == 1 && v[2] == 4322 && v[3] < 2037 ) || 
      ( try2 == 1 && v[0] == 1 &&  v[1] == 0 && v[2] == 3705 && (v[3] < 556 || (v[3] > 1000 && v[3] < 6021)) ) )
	 security_hole(port);
 }
}

NetUseDel();
