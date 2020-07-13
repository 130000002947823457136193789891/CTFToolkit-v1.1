#
# This script was written by Noam Rathaus
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11986);
 script_version("$Revision: 1.3 $");
 name["english"] = "Detect STUN Server";
 script_name(english:name["english"]);

 desc["english"] = "
We have detected that the remote host is running a STUN (Simple 
Traversal of User Datagram Protocol - RFC 3489) server.

Simple Traversal of User Datagram Protocol (UDP) Through Network
Address Translators (NATs) (STUN) is a lightweight protocol that
allows applications to discover the presence and types of NATs and
firewalls between them and the public Internet.  It also provides the
ability for applications to determine the public Internet Protocol
(IP) addresses allocated to them by the NAT.  STUN works with many
existing NATs, and does not require any special behavior from them.
As a result, it allows a wide variety of applications to work through
existing NAT infrastructure.

Risk factor : Low";

 script_description(english:desc["english"]);

 summary["english"] = "STUN Server Detection";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2004 Noam Rathaus");
 script_family(english:"Service detection");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include ("dump.inc");
debug = debug_level;

#port = get_kb_item("Services/stun");
port = 3478;
# This is UDP based protocol ...

udpsock = open_sock_udp(port);
data = raw_string(0x00, 0x01, # Binding request
                  0x00, 0x08, # Message length
                  0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89, 0x90, 0x01, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67, # Message ID
                  0x00, 0x03, # Change-Request
                  0x00, 0x04, # Attribute length
                  0x00, 0x00, 0x00, 0x00 # Not Set, Not Set
                 );

send(socket:udpsock, data:data);

response = "";

z = recv(socket:udpsock, length:1024, min:1);
if(z)
{
 if (debug)
 {
  dump(dtitle:"STUN", ddata:z);
 }

 if (z[0] == raw_string(0x01) && z[1] == raw_string(0x01)) # Binding Response
 {
  length = ord(z[2])*256 + ord(z[3]);

  if (debug)
  {
   display("length: ", length, "\n");
  }

  offset = 2+2+16;
  for (i = 0; i < length;)
  {
   count = 0;
   if (z[i+offset] == raw_string(0x00) && z[i+1+offset] == raw_string(0x01)) # Mapped address
   {
    count += 2;
    if (z[i+count+offset] == raw_string(0x00) && z[i+count+1+offset] == raw_string(0x08)) # Attribute length should be 8
    {
     count += 2;
     if (z[i+count+1+offset] == raw_string(0x01)) # IPv4
     {
      count += 2;
      port = ord(z[i+count+offset])*256+ord(z[i+count+1+offset]);
      ip = string(ord(z[i+count+2+offset]), ".", ord(z[i+count+3+offset]), ".", ord(z[i+count+4+offset]), ".", ord(z[i+count+5+offset]));
      count += 6;

      response = string(response, "Mapped Address: ", ip, ":", port, "\n");
#      display("Mapped address\n");
#      display("port: ", port, "\n");
#      display("ip: ", ip, "\n");
     }
    }
   }

   if (z[i+offset] == raw_string(0x00) && z[i+1+offset] == raw_string(0x04)) # Source Address
   {
    count += 2;
    if (z[i+count+offset] == raw_string(0x00) && z[i+count+1+offset] == raw_string(0x08)) # Attribute length should be 8
    {
     count += 2;
     if (z[i+count+1+offset] == raw_string(0x01)) # IPv4
     {
      count += 2;
      port = ord(z[i+count+offset])*256+ord(z[i+count+1+offset]);
      ip = string(ord(z[i+count+2+offset]), ".", ord(z[i+count+3+offset]), ".", ord(z[i+count+4+offset]), ".", ord(z[i+count+5+offset]));
      count += 6;

      response = string(response, "Source Address: ", ip, ":", port, "\n");
#      display("Soure Address\n");
#      display("port: ", port, "\n");
#      display("ip: ", ip, "\n");
     }
    }
   }

   if (z[i+offset] == raw_string(0x00) && z[i+1+offset] == raw_string(0x05)) # Changed Address
   {
    count += 2;
    if (z[i+count+offset] == raw_string(0x00) && z[i+count+1+offset] == raw_string(0x08)) # Attribute length should be 8
    {
     count += 2;
     if (z[i+count+1+offset] == raw_string(0x01)) # IPv4
     {
      count += 2;
      port = ord(z[i+count+offset])*256+ord(z[i+count+1+offset]);
      ip = string(ord(z[i+count+2+offset]), ".", ord(z[i+count+3+offset]), ".", ord(z[i+count+4+offset]), ".", ord(z[i+count+5+offset]));
      count += 6;

      response = string(response, "Changed Address: ", ip, ":", port, "\n");
#      display("Changed Address\n");
#      display("port: ", port, "\n");
#      display("ip: ", ip, "\n");
     }
    }
   }

   if (count == 0)
   {
    if (debug)
    {
     display("z[i(", i, ")+offset(", offset, ")]: ", ord(z[i+offset]), "\n");
    }
    i++;
   }

   i += count;
  }

  if (response)
  {
   report = "
The remote host is running a STUN (Simple Traversal of User Datagram 
Protocol - RFC 3489) server.

Simple Traversal of User Datagram Protocol (UDP) Through Network
Address Translators (NATs) (STUN) is a lightweight protocol that
allows applications to discover the presence and types of NATs and
firewalls between them and the public Internet.  It also provides the
ability for applications to determine the public Internet Protocol
(IP) addresses allocated to them by the NAT.  STUN works with many
existing NATs, and does not require any special behavior from them.
As a result, it allows a wide variety of applications to work through
existing NAT infrastructure.


" + response + "

Solution : Filter incoming traffic to this port
Risk factor : Low";
   security_note(port:port, proto:"udp", data:response);
   register_service(port: port, proto: "stun", ipproto: "udp");
   exit(0);
  }
 }
}
