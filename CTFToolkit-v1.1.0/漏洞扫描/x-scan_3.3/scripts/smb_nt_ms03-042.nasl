# This script was written by Jeff Adams <jeffrey.adams@hqda.army.mil>
# This script is Copyright (C) 2003 Jeff Adams

if(description)
{
 script_id(11887);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2003-A-0029");
 script_version("$Revision: 1.5 $");
 script_cve_id("CAN-2003-0661");
 
 name["english"] = "Buffer Overflow in Windows Troubleshooter ActiveX Control (826232)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
A security vulnerability exists in the Microsoft Local Troubleshooter ActiveX control in 
Windows 2000. The vulnerability exists because the ActiveX control (Tshoot.ocx) contains
a buffer overflow that could allow an attacker to run code of their choice on a user's system. 
To exploit this vulnerability, the attacker would have to create a specially formed HTML based 
e-mail and send it to the user. 
Alternatively an attacker would have to host a malicious Web site that contained a Web page 
designed to exploit this vulnerability.

Solution : see http://www.microsoft.com/technet/security/bulletin/ms03-042.mspx
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for hotfix Q826232";

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

if ( hotfix_check_sp(win2k:5) <= 0 ) exit(0);
if ( hotfix_missing(name:"KB826232") > 0 )
	security_hole(get_kb_item("SMB/transport"));
