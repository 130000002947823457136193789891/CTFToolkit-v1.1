#
# (C) Tenable Network Security
#

if(description)
{
 script_id(11803);
 script_bugtraq_id(7370, 8262);
 script_cve_id("CAN-2003-0346");
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2003-A-0024");
 script_version ("$Revision: 1.17 $");

 name["english"] = "DirectX MIDI Overflow (819696)";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running a version of Windows with a version of
DirectX which is vulnerable to a buffer overflow in the module
which handles MIDI files.

To exploit this flaw, an attacker needs to craft a rogue MIDI file and
send it to a user of this computer. When the user attempts to read the
file, it will trigger the buffer overflow condition and the attacker
may gain a shell on this host.

Solution : see http://www.microsoft.com/technet/security/bulletin/MS03-030.mspx
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks hotfix 819696";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
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
	( dvers != "4.09.00.0901" ) )
	exit (0);
} 


if ( vers == "5.1" )
{
  if (  ( dvers != "4.08.02.0134" ) &&
	( dvers != "4.09.00.0900" ) &&
	( dvers != "4.09.00.0901" ) )
	exit (0);
} 


if ( vers == "5.2" )
{
  if (  ( dvers != "4.09.00.0900" ) &&
	( dvers != "4.09.00.0901" ) )
	exit (0);
} 

if ( hotfix_check_sp(nt:7, win2k:4, xp:2, win2003:1) <= 0 ) exit(0);
if ( hotfix_missing(name:"KB819696") > 0 )
	security_hole(get_kb_item("SMB/transport"));


