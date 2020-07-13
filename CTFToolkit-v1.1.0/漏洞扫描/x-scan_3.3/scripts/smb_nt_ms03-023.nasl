# Script for checking MS03-023 Written by Jeff Adams <jeffrey.adams@hqda.army.mil>

if(description)
{
 script_id(11878);
 script_bugtraq_id(8016);
 script_version("$Revision: 1.8 $");
 script_cve_id("CAN-2003-0469");
 
 name["english"] = "Buffer Overrun In HTML Converter Could Allow Code Execution (823559)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
There is a flaw in the way the HTML converter for Microsoft Windows handles a 
conversion request during a cut-and-paste operation. This flaw causes a 
security vulnerability to exist. A specially crafted request to the HTML 
converter could cause the converter to fail in such a way that it could 
execute code in the context of the currently logged-in user. Because this 
functionality is used by Internet Explorer, an attacker could craft a 
specially formed Web page or HTML e-mail that would cause the HTML converter 
to run arbitrary code on a user's system. A user visiting an attacker's Web 
site could allow the attacker to exploit the vulnerability without any other 
user action.

Solution : see http://www.microsoft.com/technet/security/bulletin/ms03-023.mspx
 
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for hotfix Q823559";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"Written by Jeff Adams");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
  script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 exit(0);
}

include("smb_hotfixes.inc");

if ( hotfix_check_sp(win2k:5, xp:2, win2003:1) <= 0 ) exit(0);
if ( hotfix_missing(name:"KB823559") > 0 )
	security_hole(get_kb_item("SMB/transport"));
