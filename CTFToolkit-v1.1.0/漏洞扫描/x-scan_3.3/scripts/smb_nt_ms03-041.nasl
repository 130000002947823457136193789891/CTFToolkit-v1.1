# This script was written by Jeff Adams <jeffrey.adams@hqda.army.mil>
# This script is Copyright (C) 2003 Jeff Adams

if(description)
{
 script_id(11886);
 script_bugtraq_id(8830);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2003-B-0006");
 script_version("$Revision: 1.9 $");
 script_cve_id("CAN-2003-0660");
 
 name["english"] = "Vulnerability in Authenticode Verification Could Allow Remote Code Execution (823182)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
There is a vulnerability in Authenticode that, under certain low memory 
conditions, could allow an ActiveX control to download and install without 
presenting the user with an approval dialog. To exploit this vulnerability, 
an attacker could host a malicious Web Site designed to exploit this 
vulnerability. If an attacker then persuaded a user to visit that site an 
ActiveX control could be installed and executed on the user's system. 
Alternatively, an attacker could create a specially formed HTML e-mail and i
send it to the user. 

Exploiting the vulnerability would grant the attacker with the same privileges 
as the user.

Solution : see http://www.microsoft.com/technet/security/bulletin/ms03-041.mspx
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for hotfix Q823182";

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
if ( hotfix_missing(name:"KB823182") > 0 )
	security_hole(get_kb_item("SMB/transport"));

