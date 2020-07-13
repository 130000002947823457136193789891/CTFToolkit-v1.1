#
# This script was written by Michael Scheidell <scheidell at secnap.net>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10835);
 script_bugtraq_id(3723);
 script_version("$Revision: 1.13 $");
 script_cve_id("CVE-2001-0876");
 name["english"] = "Unchecked Buffer in XP upnp";
 
 script_name(english:name["english"]);
 
 desc["english"] = "

Unchecked Buffer in Universal Plug and Play Can
Lead to System Compromise for Windows XP (Q315000)

By sending a specially-malformed NOTIFY directive,
it would be possible for an attacker to cause code
to run in the context of the UPnP service, which
runs with system privileges on Windows XP.

The UPnP implementations do not adequately
regulate how it performs this operation, and this
gives rise to two different denial-of-service
scenarios. (CVE-2001-0877)

See http://www.microsoft.com/technet/security/bulletin/ms01-059.mspx

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Determines whether the hotfix Q315000 is installed";
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

if ( hotfix_check_sp(xp:1) <= 0 ) exit(0);
if ( hotfix_missing(name:"Q315000") > 0 )
	security_hole(get_kb_item("SMB/transport"));

