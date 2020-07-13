#
# This script was written by Michael Scheidell SECNAP Network Security
#
# See the Nessus Scripts License for details
#
if(description)
{
 script_id(11146);
 script_bugtraq_id(5410, 5711, 5712);
 script_version("$Revision: 1.9 $");
 script_cve_id("CAN-2002-0863"); # and 864

 name["english"] = "Microsoft RDP flaws could allow sniffing and DOS(Q324380)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Remote Data Protocol (RDP) version 5.0 in Microsoft
Windows 2000 and RDP 5.1 in Windows XP does not
encrypt the checksums of plaintext session data,
which could allow a remote attacker to determine the
contents of encrypted sessions via sniffing, and 
Remote Data Protocol (RDP) version 5.1 in Windows
XP allows remote attackers to cause a denial of
service (crash) when Remote Desktop is enabled via a
PDU Confirm Active data packet that does not set the
Pattern BLT command.

Impact of vulnerability: Two vulnerabilities:
information disclosure, denial of service.

Maximum Severity Rating: Moderate. 

Recommendation: Administrators of Windows
2000 terminal servers and Windows XP users
who have enabled Remote Desktop should apply
the patch.

Affected Software: 

Microsoft Windows 2000 
Microsoft Windows XP

Solution :  http://www.microsoft.com/technet/security/bulletin/ms02-051.mspx
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for MS Hotfix Q324380, Flaws in Microsoft RDP";

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

if ( hotfix_check_sp(xp:1, win2k:4) <= 0 ) exit(0);
if ( hotfix_check_nt_server() <= 0 ) exit(0);
if ( hotfix_missing(name:"Q324380") > 0 )
	security_hole(get_kb_item("SMB/transport"));

