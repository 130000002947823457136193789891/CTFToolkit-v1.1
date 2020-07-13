#
# (C) Tenable Network Security
#
# Ref: http://www.microsoft.com/technet/security/bulletin/ms02-031.mspx

if(description)
{
 script_id(11336);
 script_bugtraq_id(4821, 5063, 5064, 5066);
 script_cve_id("CVE-2002-0616", "CVE-2002-0617", "CVE-2002-0618", "CVE-2002-0619");
 
 script_version("$Revision: 1.11 $");

 name["english"] = "Cumulative patches for Excel and Word for Windows";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host has old versions of Word and Excel installed.
An attacker may use these to execute arbitrary code on this host.

To succeed, the attacker would have to send a rogue excel or word
file to the owner of this computer and have it open it.

Solution : See http://www.microsoft.com/technet/security/bulletin/ms02-031.mspx
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the version of WinWord.exe and Excel.exe";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 - 2005 Tenable Network Security");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys( "SMB/WindowsVersion", "SMB/registry_access");

 script_require_ports(139, 445);
 exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");


rootfile = hotfix_get_programfilesdir();
if ( ! rootfile ) exit(1);

share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:rootfile);
word =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1\Microsoft Office\Office\WinWord.exe", string:rootfile);
word10 =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1\Microsoft Office\Office10\WinWord.exe", string:rootfile);
excel =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1\Microsoft Office\Office\Excel.exe", string:rootfile);
excel10 = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1\Microsoft Office\Office10\Excel.exe", string:rootfile);



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

handle =  CreateFile (file:excel10, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL, share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);
if ( ! isnull(handle) )
{
 excel10_version = v =  GetFileVersion(handle:handle);
 CloseFile(handle:handle);
 if ( ! isnull(v) ) 
 {
  set_kb_item(name:"SMB/Office/Excel/Version", value:string(v[0], ".", v[1], ".", v[2], ".", v[3]));
 }
}
handle =  CreateFile (file:excel, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL, share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);
if ( ! isnull(handle) )
{
 excel_version = v =  GetFileVersion(handle:handle);
 CloseFile(handle:handle);
 if ( ! isnull(v) ) 
 {
  set_kb_item(name:"SMB/Office/Excel/Version", value:string(v[0], ".", v[1], ".", v[2], ".", v[3]));
 }
}

handle =  CreateFile (file:word10, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL, share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);
if ( ! isnull(handle) )
{
 word10_version = v =  GetFileVersion(handle:handle);
 CloseFile(handle:handle);
 if ( ! isnull(v) ) 
 {
  set_kb_item(name:"SMB/Office/Word/Version", value:string(v[0], ".", v[1], ".", v[2], ".", v[3]));
 }
}


handle =  CreateFile (file:word, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL, share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);
if ( ! isnull(handle) )
{
 word_version = v =  GetFileVersion(handle:handle);
 CloseFile(handle:handle);
 if ( ! isnull(v) ) 
 {
  set_kb_item(name:"SMB/Office/Word/Version", value:string(v[0], ".", v[1], ".", v[2], ".", v[3]));
 }
}



NetUseDel();

if ( ! isnull(excel_version) ) 
{
 if ( excel_version[0] == 9 && excel_version[1] == 0 && excel_version[2] < 6508 ) {
	security_hole(port);
	exit(0);
	}
}
if ( ! isnull(excel10_version) ) 
{
 if ( excel10_version[0] == 10 && excel10_version[1] == 0 && excel10_version[2] < 4109 ) {
	security_hole(port);
	exit(0);
	}
}
if ( ! isnull(word10_version) ) 
{
 if ( word10_version[0] == 10 && word10_version[1] == 0 && ( word10_version[2] < 4009 || (word10_version[2] == 4009 && word10_version[3] < 3501)) ) {
	security_hole(port);
	exit(0);
	}
}
