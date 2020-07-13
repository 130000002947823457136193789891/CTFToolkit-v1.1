#
# This script was written by Renaud Deraison 
#
# See the Nessus Scripts License for details
#
# MS03-030 supercedes MS02-040
#
# Note: The fix for this issue will be included in MDAC 2.5 Service Pack 5 and in MDAC 2.7 Service Pack 2. 
# The script should be update when the service pack is released.
#
# MS03-030 Prerequisites:
# You must be running one of the following versions of MDAC: 
# MDAC 2.5 Service Pack 2
# MDAC 2.5 Service Pack 3 
# MDAC 2.6 Service Pack 2
# MDAC 2.7 RTM
# MDAC 2.7 Service Pack 1
# Other versions of MDAC are not affected by this vulnerability.  
#
# MS02-040 Fixed in :
#	- MDAC 2.5 SP3
#	- MDAC 2.6 SP3
#	- MDAC 2.7 SP1
#
if(description)
{
 script_id(11301);
 script_bugtraq_id(5372, 8455);
 script_version("$Revision: 1.22 $");
 
 script_cve_id("CVE-2002-0695", "CVE-2003-0353");
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2002-A-0010");
 name["english"] = "Unchecked buffer in MDAC Function";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote Microsoft Data Access Component (MDAC) server
is vulnerable to a flaw which could allow an attacker to
execute arbitrary code on this host, provided he can
load and execute a database query on this server.

Impact of vulnerability: Elevation of Privilege 

Affected Software: 

MDAC version 2.5 Service Pack 2
MDAC version 2.5 Service Pack 3
MDAC version 2.6 Service Pack 2
MDAC version 2.7 RTM
MDAC version 2.7 Service Pack 1

Recommendation: Users using any of the affected
products should install the patch immediately.

Maximum Severity Rating: Moderate

See
http://www.microsoft.com/technet/security/bulletin/ms03-033.mspx

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the version of MDAC";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");


 exit(0);
}

include("smb_hotfixes.inc");

if ( hotfix_check_sp(xp:2) <= 0 ) exit(0);

version = hotfix_data_access_version();
if(!version)exit(0);

if ( hotfix_missing(name:"832483") > 0 &&
     hotfix_missing(name:"823718") > 0  )
	security_warning(get_kb_item("SMB/transport"));
