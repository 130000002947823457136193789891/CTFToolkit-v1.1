#
# This script was written by Michael Scheidell SECNAP Network Security
#
# See the Nessus Scripts License for details
# re-release, microsoft patched the patch, new qnumber, registry, etc

if(description)
{
 script_id(11145);
 script_bugtraq_id(5410);
 script_version("$Revision: 1.17 $");
 script_cve_id("CAN-2002-1183","CAN-2002-0862");

 name["english"] = "Certificate Validation Flaw Could Enable Identity Spoofing (Q328145)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Hotfix to fix Certificate Validation Flaw (Q329115)
is not installed.

The vulnerability could enable an attacker who had
a valid end-entity certificate to issue a
subordinate certificate that, although bogus,
would nevertheless pass validation. Because
CryptoAPI is used by a wide range of applications,
this could enable a variety of identity spoofing
attacks.
Impact of vulnerability: Identity spoofing. 

Maximum Severity Rating: Critical 

Recommendation: Administrators should install the patch immediately. 

Affected Software: 

Microsoft Windows 98 
Microsoft Windows 98 Second Edition 
Microsoft Windows Me 
Microsoft Windows NT 4.0 
Microsoft Windows NT 4.0, Terminal Server Edition 
Microsoft Windows 2000 
Microsoft Windows XP 
Microsoft Office for Mac 
Microsoft Internet Explorer for Mac 
Microsoft Outlook Express for Mac 

See
http://www.microsoft.com/technet/security/bulletin/ms02-050.mspx

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for MS Hotfix Q328145, Certificate Validation Flaw";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2002 SECNAP Network Security, LLC");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 exit(0);
}

include("smb_hotfixes.inc");

if ( hotfix_check_sp(nt:7, win2k:4, xp:2) <= 0 ) exit(0);
if ( hotfix_missing(name:"Q329115") > 0  )
	security_hole(get_kb_item("SMB/transport"));
 
