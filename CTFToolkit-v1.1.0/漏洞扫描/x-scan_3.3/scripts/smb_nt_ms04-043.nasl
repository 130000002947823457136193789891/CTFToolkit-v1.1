#
# (C) Tenable Network Security
#
if(description)
{
 script_id(15964);
 script_version("$Revision: 1.7 $");
 script_bugtraq_id(11916);
 script_cve_id("CAN-2004-0568");
 name["english"] = "Vulnerabilities in HyperTerminal (873339)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host contains a version of the HyperTerminal software which
is vulnerable to a security flaw which may allow an attacker to execute
arbitrary code on the remote host by tricking a victim into using Hyperterminal
to log into a rogue host.

Solution : http://www.microsoft.com/technet/security/bulletin/ms04-043.mspx
Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the remote registry for MS04-043";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_ports(139, 445);
 script_require_keys("SMB/Registry/Enumerated");
 exit(0);
}

include("smb_func.inc");
include("smb_hotfixes.inc");

if ( hotfix_check_nt_server() <= 0 ) exit(0);
if ( hotfix_check_sp(nt:7, xp:3, win2k:5, win2003:1) <= 0 ) exit(0);

if ( hotfix_missing(name:"873339") <= 0 ) exit(0);
	
rootfile = hotfix_get_systemroot();
if(!rootfile) exit(1);


share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:rootfile);
dll =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1\system32\hypertrm.dll", string:rootfile);

login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();
port    =  kb_smb_transport();

if(!get_port_state(port))exit(1);
soc = open_sock_tcp(port);
if(!soc)exit(1);


session_init(socket:soc, hostname:kb_smb_name());
r = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if ( r != 1 ) 
 exit(1);


handle =  CreateFile (file:dll, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL, share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);

if ( ! isnull(handle) )
{
 security_warning ( port );
 CloseFile(handle:handle);
}

NetUseDel();
