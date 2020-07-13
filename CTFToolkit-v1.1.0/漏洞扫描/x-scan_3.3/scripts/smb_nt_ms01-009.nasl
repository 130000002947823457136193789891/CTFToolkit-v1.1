#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10615);
 script_bugtraq_id(2368);
 script_version ("$Revision: 1.18 $");
 script_cve_id("CVE-2001-0017");

 
 name["english"] =  "Malformed PPTP Packet Stream vulnerability";
 name["francais"] = "Malformed PPTP Packet Stream vulnerability";
 
 script_name(english:name["english"],
 	     francais:name["francais"]);
 
 desc["english"] = "
The hotfix for the 'Malformed PPTP Packet Stream'
problem has not been applied.

This vulnerability allows an attacker to crash the WindowsNT 4.0
hosts that uses PPTP.

Solution : See http://www.microsoft.com/Downloads/Release.asp?ReleaseID=27836
Risk factor : High";


 desc["francais"] = "
Le patch pour la vulnérabilité des flux de paquets PPTP n'a pas
été installé.

Cette vulnérabilité permet à un utilisateur de faire planter
les machines WindowsNT 4.0 qui utilisent PPTP.

Solution : cf http://www.microsoft.com/Downloads/Release.asp?ReleaseID=27836
Facteur de risque : Sérieux";


 script_description(english:desc["english"],
 		    francais:desc["francais"]);
 
 summary["english"] = "Determines whether the hotfix Q283001 is installed";
 summary["francais"] = "Détermine si le hotfix Q283001 est installé";
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
if ( hotfix_missing(name:"Q299444") > 0 &&
     hotfix_missing(name:"Q283001") > 0 ) 
	security_hole(get_kb_item("SMB/transport"));
