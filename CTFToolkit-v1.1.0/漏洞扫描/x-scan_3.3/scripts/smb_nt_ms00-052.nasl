#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10486);
 script_bugtraq_id(1507);
 script_version ("$Revision: 1.23 $");
 script_cve_id("CVE-2000-0663");
 name["english"] =  "Relative Shell Path patch";
 name["francais"] = "Relative Shell Path patch";
 
 script_name(english:name["english"],
 	     francais:name["francais"]);
 
 desc["english"] = "
The hotfix for the 'Relative Shell Path'
vulnerability has not been applied.

This vulnerability allows a malicious user
who can write to the remote system root
to cause the code of his choice to be executed by
the users who will interactively log into this
host.


Solution : See http://www.microsoft.com/technet/security/bulletin/ms00-052.mspx
Risk factor : Medium";


 desc["francais"] = "
Le hotfix pour le problème du 'chemin relatif
vers le shell' n'a pas été appliqué.

Cette vulnérabilité permet à un pirate ayant la
possibilité d'écrire à la racine du disque système
distant de faire executer le programme de son
choix par les utilisateurs se connectant
interactivement à cette machine.

Solution : cf http://www.microsoft.com/technet/security/bulletin/ms00-052.mspx
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
 exit(0);
}


include("smb_hotfixes.inc");

if ( hotfix_check_sp(nt:7, win2k:2) <= 0 ) exit(0);
if ( hotfix_missing(name:"Q299444") > 0 &&
     hotfix_missing(name:"Q269049") > 0 )
	{
	 security_warning(get_kb_item("SMB/transport"));
	}
