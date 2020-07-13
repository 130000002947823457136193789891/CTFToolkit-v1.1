#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10499);
 script_bugtraq_id(1613);
 script_version ("$Revision: 1.19 $");
 script_cve_id("CVE-2000-0771");

 name["english"] =  "Local Security Policy Corruption";
 name["francais"] = "Local Security Policy Corruption";
 
 script_name(english:name["english"],
 	     francais:name["francais"]);
 
 desc["english"] = "
The hotfix for the 'Local Security Policy Corruption'
problem has not been applied.

This vulnerability allows a malicious user to corrupt parts of
a Windows 2000 system's local security policy, which may
prevent this host from communicating with other hosts
in this domain.

Solution : See http://www.microsoft.com/technet/security/bulletin/ms00-062.mspx
Risk factor : Medium";


 desc["francais"] = "
Le hotfix pour le problème de corruption de LSA n'a pas été appliqué.

Cette vulnérabilité permet à un utilisateur malicieux de corrompre
la LSA, ce qui empechera ce poste de communiquer avec les autres
appartenant à ce domaine.

Solution : cf http://www.microsoft.com/technet/security/bulletin/ms00-062.mspx
Facteur de risque : Moyen";


 script_description(english:desc["english"],
 		    francais:desc["francais"]);
 
 summary["english"] = "Determines whether the hotfix Q269609 is installed";
 summary["francais"] = "Détermine si le hotfix Q269609 est installé";
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

if ( hotfix_check_sp(win2k:1) <= 0 ) exit(0);

if ( hotfix_missing(name:"Q269609") > 0 ) 
	security_warning(get_kb_item("SMB/transport"));
