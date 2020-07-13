#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
#
# MS01-011 was superceded by MS01-036

if(description)
{
 script_id(10619);
 script_bugtraq_id(2929);
 script_version ("$Revision: 1.22 $");
 script_cve_id("CVE-2001-0502");
 
 name["english"] =  "Malformed request to domain controller";
 name["francais"] = "Malformed request to domain controller";
 
 script_name(english:name["english"],
 	     francais:name["francais"]);
 
 desc["english"] = "
The hotfix for the 'Malformed request to domain controller'
problem has not been applied.

This vulnerability can allow an attacker to disable temporarily
a Windows 2000 domain controller.

Solution : See http://www.microsoft.com/technet/security/bulletin/ms01-036.mspx
Risk factor : High";


 desc["francais"] = "
Le patch pour la vulnérabilité des de paquets de requete de controlleur
de domaine n'a pas été installé.

Cette vulnérabilité permet à un pirate de désactiver temporairement le
controlleur de domaine distant.

Solution : cf http://www.microsoft.com/technet/security/bulletin/ms01-036.mspx
Facteur de risque : Sérieux";


 script_description(english:desc["english"],
 		    francais:desc["francais"]);
 
 summary["english"] = "Determines whether the hotfix Q287397 is installed";
 summary["francais"] = "Détermine si le hotfix Q287397 est installé";
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

if ( hotfix_check_domain_controler() <= 0 ) exit(0);
if ( hotfix_check_sp(win2k:3) <= 0 ) exit(0);
if ( hotfix_missing(name:"SP2SPR1") > 0 && hotfix_missing(name:"Q299687") > 0 )
	security_hole(get_kb_item("SMB/transport"));
