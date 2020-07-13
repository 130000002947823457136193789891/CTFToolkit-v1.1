#
# (C) Tenable Network Security
#

account = "mpi";
password = "";

if(description)
{
 script_id(18527);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CAN-2005-1379");
 script_bugtraq_id(13431);
 
 script_name(english:string("Unpassworded ", account, " account"));

 script_description(english:string("
The account '", account, "' has no password set.
An attacker may use it to gain further privileges on this system

Risk factor : High
Solution : Set a password for this account or disable it"));
		 
script_summary(english:"Logs into the remote host",
	       francais:"Translate");

 script_category(ACT_GATHER_INFO);

 script_family(english:"Default Unix Accounts");
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 
 
 script_dependencie("find_service.nes");
 script_require_ports("Services/telnet", 23, "Services/ssh", 22);
 exit(0);
}

#
# The script code starts here : 
#
include("ssh_func.inc");
include("default_account.inc");
include("global_settings.inc");

if ( thorough_tests )
{
 port = check_account(login:account, password:password);
 if(port)security_hole(port);
}
