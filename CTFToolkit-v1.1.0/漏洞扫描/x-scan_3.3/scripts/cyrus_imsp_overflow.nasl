#
# This script was written by Noam Rathaus <noam@beyondsecurity.com>
#
# See the Nessus Scripts License for details
#
#
# Changes by rd :
# - description
# - minor bugfixes
#
# From: Felix Lindner [felix.lindner@nruns.com]
# Subject: Cyrus IMSP remote root vulnerability
# Date: Monday 15/12/2003 20:56

if(description)
{
 script_id(11953);
 script_version ("$Revision: 1.1 $");
 
 name["english"] = "cyrus-imsp abook_dbname buffer overflow";
 script_name(english:name["english"]);

 desc["english"] = "
The remote host is running a version of cyrus-imsp (Internet Message Support
Protocol) which has a buffer overflow bug.

An attacker could exploit this bug to execute arbitrary code on this system
with the privileges of the root user.

The overflow occurs when the user issues a too long argument as his name, 
causing an overflow in the abook_dbname function command.

Risk factor : High
Solution : Upgrade cyrus-imsp server to version version 1.6a4 or 1.7a";

 script_description(english:desc["english"]);
 
 summary["english"] = "cyrus-imsp abook_dbname buffer overflow"; 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2003 Noam Rathaus");
 
 family["english"] = "Gain root remotely";
 
 script_family(english:family["english"]);
	       
 script_dependencie("find_service.nes");
 script_require_ports("Services/imsp", 406);
 exit(0);
}

#
# The script code starts here
#


port = get_kb_item("Services/imsp");
if(!port)port = 406;
# display("port: ", port, "\n");

if(get_port_state(port))
 { 
#  display("connected\n");
  soc = open_sock_tcp(port);
  if(!soc)exit(0);
  banner = recv_line(socket:soc, length:4096);
  close(soc);
}

# display("banner: ", banner, "\n");

if(banner)
{
 if( ereg(pattern:".* Cyrus IMSP version (0\..*|1\.[0-5]|1\.6|1\.6a[0-3]|1\.7) ready", string:banner) )
 {
  security_hole(port);
 }
}
