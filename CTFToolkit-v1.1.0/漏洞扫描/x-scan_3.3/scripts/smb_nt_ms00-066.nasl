#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10509);
 script_bugtraq_id(1304);
 script_version ("$Revision: 1.17 $");

 script_cve_id("CAN-2000-0544");
 name["english"] =  "Malformed RPC Packet patch";
 name["francais"] = "Malformed RPC Packet patch";
 
 script_name(english:name["english"],
 	     francais:name["francais"]);
 
 desc["english"] = "
The hotfix for the 'Malformed RPC Packet' 
problem has not been applied.

This vulnerability allows a malicious user,  to cause
a denial of service against this host.

Solution : See http://www.microsoft.com/technet/security/bulletin/ms00-066.mspx
Risk factor : Medium";


 desc["francais"] = "
Le hotfix pour le problème de paquet RPC mal formé n'a pas
été installé.

Cette vulnérabilité permet a un pirate de causer un déni de service
contre ce serveur.

Solution : cf http://www.microsoft.com/technet/security/bulletin/ms00-066.mspx
Facteur de risque : Moyen";


 script_description(english:desc["english"],
 		    francais:desc["francais"]);
 
 summary["english"] = "Determines whether the hotfix Q272303 is installed";
 summary["francais"] = "Détermine si le hotfix Q272303 est installé";
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

if ( hotfix_check_sp(win2k:2) <= 0 ) exit(0);
if ( hotfix_missing(name:"Q272303") > 0 )
	security_warning(get_kb_item("SMB/transport"));

