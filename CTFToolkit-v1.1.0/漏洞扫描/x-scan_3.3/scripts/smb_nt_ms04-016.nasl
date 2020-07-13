#
# Noam Rathaus noamr@beyondsecurity.com
#
if(description)
{
 script_id(12267);
 script_bugtraq_id(10487);
 script_cve_id("CAN-2004-0202");
 script_version("$Revision: 1.8 $");
 name["english"] = "Vulnerability in DirectPlay Could Allow Denial of Service (839643)";

 script_name(english:name["english"]);

 desc["english"] = "
A denial of service vulnerability exists in the implementation of the
IDirectPlay4 application programming interface (API) of Microsoft DirectPlay
because of a lack of robust packet validation.

If a user is running a networked DirectPlay application,
an attacker who successfully exploited this vulnerability could
cause the DirectPlay application to fail. The user would have
to restart the application to resume functionality.

Solution : http://www.microsoft.com/technet/security/bulletin/ms04-016.mspx
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for ms04-016 over the registry";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Noam Rathaus");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 exit(0);
}

include("smb_hotfixes.inc");

vers = get_kb_item("SMB/WindowsVersion");
if ( !vers ) exit(0);

dvers = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/DirectX/Version");
if ( !dvers ) exit(0);

if ( vers == "5.0" )
{
  if (  ( dvers != "4.08.00.0400" ) &&
	( dvers != "4.08.00.0400" ) &&
	( dvers != "4.08.01.0881" ) &&
	( dvers != "4.08.01.0901" ) &&
	( dvers != "4.08.02.0134" ) &&
	( dvers != "4.09.00.0900" ) &&
	( dvers != "4.09.00.0901" ) &&
	( dvers != "4.09.00.0902" ) )
	exit (0);
} 


if ( vers == "5.1" )
{
  if (  ( dvers != "4.08.02.0134" ) &&
	( dvers != "4.09.00.0900" ) &&
	( dvers != "4.09.00.0901" ) &&
	( dvers != "4.09.00.0902" ) )
	exit (0);
} 


if ( vers == "5.2" )
{
  if (  ( dvers != "4.09.00.0900" ) &&
	( dvers != "4.09.00.0901" ) &&
	( dvers != "4.09.00.0902" ) )
	exit (0);
} 

if ( hotfix_check_sp(win2k:5, xp:2, win2003:1) <= 0 ) exit(0);
if ( hotfix_missing(name:"KB839643") > 0 &&
     hotfix_missing(name:"KB839643-DirectX8") > 0 &&
     hotfix_missing(name:"KB839643-DirectX81") > 0 &&
     hotfix_missing(name:"KB839643-DirectX82") > 0 &&
     hotfix_missing(name:"KB839643-DirectX9")  > 0 )
	security_hole(get_kb_item("SMB/transport"));

