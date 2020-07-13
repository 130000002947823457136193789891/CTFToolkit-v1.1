#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10525);
 script_bugtraq_id(1743);
 script_version ("$Revision: 1.19 $");
 name["english"] = "LPC and LPC Ports Vulnerabilities patch";
 name["francais"] = "Patch pour les vulnerabilité LPC et LPC ports";
 
 script_name(english:name["english"],
 	     francais:name["francais"]);
 
 desc["english"] = "
The hotfix for the multiple LPC and LPC Ports vulnerabilities 
has not been applied on the remote Windows host.

These vulnerabilities allows an attacker gain privileges on the
remote host, or to crash it remotely.


Solution : See http://www.microsoft.com/technet/security/bulletin/ms00-070.mspx
Risk factor : High";


 desc["francais"] = "
Le hotfix corrigeant les multiples vulnérabilité LPC et LPC ports
n'a pas été appliqué sur le WindowsNT distant.

Ces vulnérabilités permettent à un pirate d'obtenir plus de privilèges
sur la machine distante, ou bien de la faire planter à distance.

Solution : cf http://www.microsoft.com/technet/security/bulletin/ms00-070.mspx
Facteur de risque : Elevé";


 script_description(english:desc["english"],
 		    francais:desc["francais"]);
 
 summary["english"] = "Determines whether the hotfix Q266433 is installed";
 summary["francais"] = "Détermine si le hotfix Q266433 est installé";
 script_summary(english:summary["english"],
 		francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 exit(0);
}

include("smb_hotfixes.inc");


if ( hotfix_check_sp(nt:7, win2k:2) <= 0 ) exit(0);
if ( hotfix_missing(name:"Q299444") > 0 &&
     hotfix_missing(name:"Q266433") > 0 ) 
	security_hole(get_kb_item("SMB/transport"));
