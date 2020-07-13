#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10434);
 script_bugtraq_id(1262);
 script_version ("$Revision: 1.22 $");
 script_cve_id("CVE-2000-0404");
 name["english"] = "NT ResetBrowser frame & HostAnnouncement flood patch";
 name["francais"] = "Patch ResetBrowser frame & HostAnnouncement flood";
 
 script_name(english:name["english"],
 	     francais:name["francais"]);
 
 desc["english"] = "
The hotfix for the 'ResetBrowser Frame' and the 'HostAnnouncement flood'
has not been applied.

The first of these vulnerabilities allows anyone to shut
down the network browser of this host at will.

The second vulnerability allows an attacker to
add thousands of bogus entries in the master browser,
which will consume most of the network bandwidth as
a side effect.


Solution : See http://www.microsoft.com/technet/security/bulletin/ms00-036.mspx
Risk factor : Medium";


 desc["francais"] = "
Le hotfix pour les vulnérabilités 'ResetBrowser Frame' et
'HostAnnouncement flood' n'a pas été appliqué.

La première de ces vulnérabilités permet à n'importe
qui d'éteindre le network browser de cette machine.

La seconde permet à un pirate d'ajouter des milliers
d'entrées bidons dans le master browser, ce qui finit
par créer un traffic réseau très important, pouvant
saturer le réseau local.

Solution : cf http://www.microsoft.com/technet/security/bulletin/ms00-036.mspx
Facteur de risque : Moyen";


 script_description(english:desc["english"],
 		    francais:desc["francais"]);
 
 summary["english"] = "Determines whether the hotfix Q262694 is installed";
 summary["francais"] = "Détermine si le hotfix Q262694 est installé";
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


if ( hotfix_check_sp(nt:7, win2k:2) <= 0 ) exit(0);
if ( hotfix_missing(name:"Q299444") > 0 &&
     hotfix_missing(name:"Q262694") > 0 )
		security_warning(port);

