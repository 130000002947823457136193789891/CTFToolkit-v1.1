#
# This script was written by Noam Rathaus
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11987);
 script_version("$Revision: 1.6 $");
 name["english"] = "Detect FSP Compatible Hosts";
 script_name(english:name["english"]);

 desc["english"] = "
The remote host is running a FSP (File Service Protocol)
compatible product. FSP is a protocol designed to serve file on top 
of the UDP protocol.

More information can be found here : http://fsp.sourceforge.net/
Risk factor : Low";

 script_description(english:desc["english"]);

 summary["english"] = "FSP Detection";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2004 Noam Rathaus");
 script_family(english:"Service detection");
 exit(0);
}


include("misc_func.inc");

ports = make_list(21, 2000, 2221);
for ( i = 0 ; ports[i] ; i ++ )
{
 # This is UDP based protocol ...
 udpsock[i] = open_sock_udp(ports[i]);
 data = raw_string(0x10, 0x44, 0xF0, 0x33, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00);
 send(socket:udpsock[i], data:data);
}

for ( i = 0 ; ports[i] ; i ++ )
{
 if ( i == 0 ) z = recv(socket:udpsock, length:1024);
 else z = recv(socket:udpsock, length:1024, timeout:0);

if(z)
{
 if (z[0] == raw_string(0x10))
 {
  mlen = ord(z[7]);
  Server = "";
  for (i = 0; i < mlen - 1; i++)
   Server = string(Server, z[12+i]);

  Server -= string("\n");
  if(!get_kb_item(string("fsp/banner/", port)))
   set_kb_item(name:string("fsp/banner/", port), value:Server);

  report = "
The remote host is running a FSP (File Service Protocol)
compatible product. FSP is a protocol designed to serve file on top 
of the UDP protocol.

The remote server banner is : " + Server + "

More information can be found here : http://fsp.sourceforge.net/
Risk factor : Low";
  security_warning(port:port, data:report, protocol:"udp");
  register_service(port: port, ipproto: "udp", proto: "fsp");
  exit(0);
  }
 }
}
