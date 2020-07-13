# This script was written by Jeff Adams <jeffrey.adams@hqda.army.mil>
# This script is Copyright (C) 2003 Jeff Adams

if(description)
{
 script_id(11885);
 script_bugtraq_id(8827);
 script_version("$Revision: 1.12 $");
 script_cve_id("CAN-2003-0659");
 
 name["english"] = "Buffer Overrun in the ListBox and in the ComboBox (824141)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
A vulnerability exists because the ListBox control and the ComboBox control 
both call a function, which is located in the User32.dll file, that contains 
a buffer overrun. An attacker who had the ability to log on to a system 
interactively could run a program that could send a specially-crafted Windows 
message to any applications that have implemented the ListBox control or the 
ComboBox control, causing the application to take any action an attacker 
specified. An attacker must have valid logon credentials to exploit the 
vulnerability. This vulnerability could not be exploited remotely. 


Solution : see http://www.microsoft.com/technet/security/bulletin/ms03-045.mspx

Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for hotfix Q824141";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Jeff Adams");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 exit(0);
}

include("smb_hotfixes.inc");

if ( hotfix_check_sp(win2k:5, xp:2, win2003:1) <= 0 ) exit(0);
if ( hotfix_check_sp(xp:2, nt:7) > 0 )
{
 if ( hotfix_missing(name:"840987") == 0 ) exit(0);
}

if ( hotfix_check_sp(win2k:5) > 0 )
{
 if ( hotfix_missing(name:"840987") == 0 ) exit(0);
 if ( hotfix_missing(name:"841533") == 0 ) exit(0);
 if ( hotfix_missing(name:"890859") == 0 ) exit(0);
}

if ( hotfix_missing(name:"824141") > 0 )
	security_warning(get_kb_item("SMB/transport"));

