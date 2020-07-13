#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10708);;
 script_bugtraq_id(3078);
 script_cve_id("CVE-2001-0553");
 script_version ("$Revision: 1.12 $");
 
 name["english"] = "SSH 3.0.0";
 name["francais"] = "SSH 3.0.0";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
You are running SSH 3.0.0. 

There is a bug in this release which allows any user
to log into accounts whose password entry is two chars
long or less.

An attacker may gain root privileges using this flaw

Solution :
Upgrade to version 3.0.1 of SSH which solves this problem.

Risk factor : High";
	
	


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the remote SSH version";
 summary["francais"] = "Vérifie la version de SSH";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2001 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2001 Renaud Deraison");
 family["english"] = "Gain a shell remotely";
 family["francais"] = "Obtenir un shell à distance";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("ssh_detect.nasl");
 script_require_ports("Services/ssh", 22);
 exit(0);
}

#
# The script code starts here
#
include("backport.inc");


port = get_kb_item("Services/ssh");
if(!port)port = 22;

banner = get_kb_item("SSH/banner/" + port );
if ( ! banner ) exit(0);


banner = tolower(get_backport_banner(banner:banner));

if("openssh" >< banner)exit(0);

if("3.0.0" >< banner)security_hole(port);
