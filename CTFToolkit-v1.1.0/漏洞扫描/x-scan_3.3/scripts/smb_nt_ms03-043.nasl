# This script was written by Jeff Adams <jeffrey.adams@hqda.army.mil>
# This script is Copyright (C) 2003 Jeff Adams

if(description)
{
 script_id(11888);
 script_bugtraq_id(8826);
 script_version("$Revision: 1.11 $");
 script_cve_id("CAN-2003-0717");
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2003-B-0007");
 
 name["english"] = "Buffer Overrun in Messenger Service (828035)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
A security vulnerability exists in the Messenger Service that could allow 
arbitrary code execution on an affected system. An attacker who successfully 
exploited this vulnerability could be able to run code with Local System 
privileges on an affected system, or could cause the Messenger Service to fail.
Disabling the Messenger Service will prevent the possibility of attack. 

This plugin determined by reading the remote registry that the patch
MS03-043 has not been applied.

Solution : see http://www.microsoft.com/technet/security/bulletin/ms03-043.mspx
 
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for hotfix Q828035";

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

if ( hotfix_check_sp(nt:7, win2k:5, xp:2, win2003:1) <= 0 ) exit(0);
if ( hotfix_missing(name:"KB828035") > 0  )
	security_hole(get_kb_item("SMB/transport"));

