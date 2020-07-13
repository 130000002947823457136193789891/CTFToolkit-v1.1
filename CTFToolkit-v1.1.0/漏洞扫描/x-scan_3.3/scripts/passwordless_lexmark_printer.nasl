#
# (C) Tenable Network Security
#

if(description)
{
 script_id(12236);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CAN-1999-1061");

 name["english"] = "Passwordless Lexmark Printer";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote printer has no password set. An attacker may abuse
it to re-configure it and thus prevent it from working properly.
An attacker may also change its IP to make it conflict with another
device on your network.

Solution : telnet to this port and set a password immediately
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Notifies that the remote printer has no password";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Misc.";
 family["francais"] = "Divers";
 script_family(english:family["english"], francais:family["francais"]);
 script_require_ports(9000);
 exit(0);
}

#
# The script code starts here
#

port = 9000;
if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
  {
   buf = telnet_init(soc);
   close(soc);
   if ("This session allows you to set the TCPIP parameters for your" >< buf )
   {
     security_hole(port);
     exit(0);
   }
  }
}  
