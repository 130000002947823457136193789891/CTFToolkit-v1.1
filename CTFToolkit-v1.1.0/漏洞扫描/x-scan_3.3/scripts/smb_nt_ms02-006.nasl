#
# This script was written by Michael Scheidell <scheidell at secnap.net>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10865);
 script_version("$Revision: 1.16 $");
 script_cve_id("CAN-2002-0053");
 name["english"] = "Checks for MS HOTFIX for snmp buffer overruns";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
There is an Unchecked Buffer in SNMP Service 
and this checks to see if the Microsoft Patch
has been applied (only checks NT/Win2k and XP PRo).

Impact of vulnerability: Run code of attacker's choice
and denial of service attacks.

Also may run snmp detect to see if snmp is running on this host.

Recommendation: Customers should install the patch immediately
or disable snmp (you should disable all unused services)

Affected Software: 

Microsoft Windows 95 
Microsoft Windows 98 
Microsoft Windows 98SE 
Microsoft Windows NT 4.0 
Microsoft Windows NT 4.0 Server, Terminal Server Edition 
Microsoft Windows 2000 
Microsoft Windows XP 

See http://www.microsoft.com/technet/security/bulletin/ms02-006.mspx
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Determines whether the hotfix Q314147 is installed";
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

if ( hotfix_check_sp(nt:7, win2k:3, xp:1) <= 0 ) exit(0);
if ( hotfix_missing(name:"Q314147") > 0 )
	security_hole(get_kb_item("SMB/transport"));

