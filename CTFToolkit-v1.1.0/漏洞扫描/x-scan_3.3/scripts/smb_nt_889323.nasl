#
# (C) Tenable Network Security
#
if(description)
{
 script_id(17607);
 script_version("$Revision: 1.2 $");
 script_bugtraq_id(12889);
 name["english"] = "Non administrators can shut down Windows XP SP1 thru TSShutdn.exe (889323)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote version of Microsoft Windows XP SP1 lacks the security update 
889323.

A non-administrative user can remotely shut down the remote host by using
the TSShutdn.exe command.

Solution : http://support.microsoft.com/kb/889323/
Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the remote registry for KB 889323";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 exit(0);
}

include("smb_hotfixes.inc");


# Only XP SP1 affected
if ( hotfix_check_sp(xp:2) <= 0 ) exit(0);

if ( hotfix_missing(name:"889323") > 0 )
	security_warning(get_kb_item("SMB/transport"));
