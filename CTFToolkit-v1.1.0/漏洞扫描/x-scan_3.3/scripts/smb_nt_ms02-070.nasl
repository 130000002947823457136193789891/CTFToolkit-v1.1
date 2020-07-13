#
# This script was written by Michael Scheidell SECNAP Network Security
#
# See the Nessus Scripts License for details

if(description)
{
 script_id(11215);
 script_bugtraq_id(6367);
 script_cve_id("CAN-2002-1256");
 script_version("$Revision: 1.9 $");

 name["english"] = "Flaw in SMB Signing Could Enable Group Policy to be Modified (329170)";

 script_name(english:name["english"]);
 
 desc["english"] = "
The SMB signing capability in the Server Message Block
protocol in Microsoft Windows 2000 and Windows XP allows
attackers to disable the digital signing settings in an
SMB session to force the data to be sent unsigned, then
inject data into the session without detection, e.g. by
modifying group policy information sent from a domain
controller.

Maximum Severity Rating: Moderate

Recommendation: Administrators should install the patch immediately. 

Affected Software: 

Microsoft Windows 2000
Microsoft Windows XP

See
http://www.microsoft.com/technet/security/bulletin/ms02-070.mspx

Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for MS Hotfix 329170";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 SECNAP Network Security");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 exit(0);
}

include("smb_hotfixes.inc");

if ( hotfix_check_sp(xp:2) == 0 && hotfix_missing(name:"896422") == 0 ) exit(0);

if ( hotfix_check_sp(nt:7, win2k:4, xp:2) <= 0 ) exit(0);
if ( hotfix_missing(name:"Q329170") > 0 )
	security_warning(get_kb_item("SMB/transport"));
