#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10632);
 script_bugtraq_id(1912);
 script_version ("$Revision: 1.19 $");
 script_cve_id("CVE-2000-0886");

 
 name["english"] =  "Webserver file request parsing";
 name["francais"] = "Webserver file request parsing";
 
 script_name(english:name["english"],
 	     francais:name["francais"]);
 
 desc["english"] = "
The hotfix for the 'Webserver file request parsing'
problem has not been applied.

This vulnerability can allow an attacker to make the
remote IIS server make execute arbitrary commands.

Solution : See http://www.microsoft.com/technet/security/bulletin/ms00-086.mspx
Risk factor : High";


 desc["francais"] = "
Le patch pour la vulnérabilité du parsing de requetes de fichiers
par le web n'a pas été appliqué.

Celle-ci permet à un pirate de faire executer des commandes arbitraires
au serveur web distant.

Solution : cf http://www.microsoft.com/technet/security/bulletin/ms00-086.mspx
Facteur de risque : Sérieux";


 script_description(english:desc["english"],
 		    francais:desc["francais"]);
 
 summary["english"] = "Determines whether the hotfix Q277873 is installed";
 summary["francais"] = "Détermine si le hotfix Q277873 est installé";
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

if ( hotfix_check_sp(nt:7, win2k:2) <= 0 ) exit(0);
if ( (hotfix_missing(name:"293826") <= 0) || 
     (hotfix_missing(name:"295534") <= 0) || 
     (hotfix_missing(name:"301625") <= 0) || 
     (hotfix_missing(name:"317636") <= 0) ||
     (hotfix_missing(name:"299444") <= 0) ||
     (hotfix_missing(name:"SP2SRP1") <= 0) ) exit(0);
if ( hotfix_missing(name:"Q277873") > 0 )
	security_hole(get_kb_item("SMB/transport"));

