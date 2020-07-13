#
# This script was written by Michael Scheidell <scheidell at secnap.net>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10866);
 script_bugtraq_id(3699);
 script_version("$Revision: 1.17 $");
 script_cve_id("CVE-2002-0057");
 name["english"] = "XML Core Services patch (Q318203)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
XMLHTTP Control Can Allow Access to Local Files.

A flaw exists in how the XMLHTTP control applies IE security zone
settings to a redirected data stream returned in response to a
request for data from a web site. A vulnerability results because
an attacker could seek to exploit this flaw and specify a data
source that is on the user's local system. The attacker could
then use this to return information from the local system to the
attacker's web site. 

Impact of vulnerability: Attacker can read files on client system.

Affected Software: 

Microsoft XML Core Services versions 2.6, 3.0, and 4.0.
An affected version of Microsoft XML Core Services also
ships as part of the following products: 

Microsoft Windows XP 
Microsoft Internet Explorer 6.0 
Microsoft SQL Server 2000 

(note: versions earlier than 2.6 are not affected
files affected include msxml[2-4].dll and are found
in the system32 directory. This might be false
positive if you have earlier version)

See http://www.microsoft.com/technet/security/bulletin/ms02-008.mspx

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Determines whether the XML Core Services patch Q318202/Q318203 is installed";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2002 Michael Scheidell");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 exit(0);
}

include("smb_hotfixes.inc");


if ( hotfix_check_sp(nt:7, win2k:5, xp:1) <= 0 ) exit(0);

if ( hotfix_missing(name:"Q832483") > 0 &&
     hotfix_missing(name:"Q318202") > 0 &&
     hotfix_missing(name:"Q318203") > 0 &&
     hotfix_missing(name:"Q317244") > 0 )
	security_hole(get_kb_item("SMB/transport"));
