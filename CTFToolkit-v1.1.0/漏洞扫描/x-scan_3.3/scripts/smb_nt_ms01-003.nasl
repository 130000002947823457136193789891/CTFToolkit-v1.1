#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10603);
 script_bugtraq_id(2303);
 script_version ("$Revision: 1.18 $");
 script_cve_id("CVE-2001-0006");
 
 name["english"] =  "Winsock Mutex vulnerability";
 name["francais"] = "Winsock Mutex vulnerability";
 
 script_name(english:name["english"],
 	     francais:name["francais"]);
 
 desc["english"] = "
The hotfix for the 'WinSock Mutex'
problem has not been applied.

This vulnerability allows a local user to prevent this host
from communicating with the network

Solution : See http://www.microsoft.com/technet/security/bulletin/ms01-003.mspx
Risk factor : High";


 desc["francais"] = "
Le patch pour la vulnérabilité des mutex winsock n'a pas
été installé.

Cette vulnérabilité permet à un utilisateur local d'empecher cette machine
de communiquer avec le réseau.

Solution : cf http://www.microsoft.com/technet/security/bulletin/ms01-003.mspx
Facteur de risque : Sérieux";


 script_description(english:desc["english"],
 		    francais:desc["francais"]);
 
 summary["english"] = "Determines whether the hotfix Q279336 is installed";
 summary["francais"] = "Détermine si le hotfix Q27 est installé";
 script_summary(english:summary["english"],
 		francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2001 Renaud Deraison");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 exit(0);
}

include("smb_hotfixes.inc");

if ( hotfix_check_sp(nt:7) <= 0 ) exit(0);
if ( hotfix_missing(name:"Q299444") > 0 && hotfix_missing(name:"Q279336") > 0 ) 
	security_hole(get_kb_item("SMB/transport"));
