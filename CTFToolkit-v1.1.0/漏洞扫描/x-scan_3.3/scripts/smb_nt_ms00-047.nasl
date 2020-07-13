#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10482);
 script_bugtraq_id(1514, 1515);
 script_version ("$Revision: 1.21 $");
 script_cve_id("CVE-2000-0673");
 name["english"] =  "NetBIOS Name Server Protocol Spoofing patch";
 name["francais"] = "NetBIOS Name Server Protocol Spoofing patch";
 
 script_name(english:name["english"],
 	     francais:name["francais"]);
 
 desc["english"] = "
The hotfix for the 'NetBIOS Name Server Protocol Spoofing'
problem has not been applied.

This vulnerability allows a malicious user to make this
host think that its name has already been taken on the
network, thus preventing it to function properly as
a SMB server (or client).



Solution : See http://www.microsoft.com/technet/security/bulletin/ms00-047.mspx
or Security Rollup: http://support.microsoft.com/support/kb/articles/q299/4/44.asp

Risk factor : Medium";


 desc["francais"] = "
Le hotfix pour le problème de spoof du protocole du
serveur de noms NetBIOS n'a pas été appliqué.

Cette vulnérabilité permet à un pirate de faire croire
à ce serveur que son nom NetBIOS a déjà été pris
par une autre machine sur le réseau, ce qui l'empeche
de s'établir en tant que serveur ou client SMB.

Solution : cf http://www.microsoft.com/technet/security/bulletin/ms00-047.mspx
Facteur de risque : Moyen";


 script_description(english:desc["english"],
 		    francais:desc["francais"]);
 
 summary["english"] = "Determines whether the hotfix Q269239 is installed";
 summary["francais"] = "Détermine si le hotfix Q269239 est installé";
 script_summary(english:summary["english"],
 		francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}


include("smb_hotfixes.inc");

if  ( hotfix_check_sp(nt:7, win2k:2) <= 0 ) exit(0);
if  ( hotfix_missing(name:"Q299444") > 0 &&
      hotfix_missing(name:"Q269239") > 0 ) 
	{
	 security_warning(get_kb_item("SMB/transport"));
	}

