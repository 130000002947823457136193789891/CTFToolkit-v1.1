#
# This script was written by Noam Rathaus
#
#
# See the Nessus Scripts License for details
#

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(15715);
 script_version("$Revision: 1.5 $");
 script_name(english:"Nortel Default Username and Password");
	     

 desc["english"] = "
The username/password combination 'ro/ro' or 'rwa/rwa' are valid.

These username and password are the default ones for many of
Nortel's network devices.

Solution : Set a strong password for the account
Risk Factor : High";

 script_description(english:desc["english"]);
 
 script_summary(english:"Logs into the remote host");

 script_category(ACT_GATHER_INFO);

 script_family(english:"Misc.");
 
 script_copyright(english:"This script is Copyright (C) 2004 Noam Rathaus");
 
 script_dependencie("ssh_detect.nasl");
 script_require_ports("Services/ssh", 22);
 script_require_keys("Settings/Thorough");
 exit(0);
}

#
# The script code starts here : 
#
include("ssh_func.inc");
include("global_settings.inc");

if ( ! thorough_tests ) exit(0);

port = kb_ssh_transport();
if ( ! port || !get_port_state(port) ) exit(0);
if ( ! get_kb_item("SSH/banner/" + port) ) exit(0);

soc = open_sock_tcp(port);
if ( ! soc ) exit(0);
ret = ssh_login(socket:soc, login:"ro", password:"ro");
close(soc);
if ( ret == 0 ) { security_hole(port); exit(0); }

soc = open_sock_tcp(port);
if ( ! soc ) exit(0);
ret = ssh_login(socket:soc, login:"rwa", password:"rwa");
close(soc);
if ( ret == 0 ) security_hole(port);

