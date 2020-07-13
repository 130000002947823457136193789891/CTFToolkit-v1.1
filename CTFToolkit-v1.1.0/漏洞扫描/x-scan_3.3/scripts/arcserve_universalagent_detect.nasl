#
#
# This script is (C) Tenable Network Security
#
#

if (description)
{
 script_id(18040);
 script_version ("$Revision: 1.1 $");
 script_name(english:"ARCServe UniversalAgent detection");
 desc["english"] = "

This plugin detects the presence of BrightStor ARCServe UniversalAgent.

Solution : Filter incoming traffic to this port to make sure only authorized
hosts can connect to it

Risk factor : None";

 script_description(english:desc["english"]);
 script_summary(english:"Determine if a remote host is running BrightStor ARCServe UniversalAgent");
 script_category(ACT_GATHER_INFO);
 script_family(english:"Service detection");
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 script_require_ports (6050);
 exit(0);
}

port = 6050;
soc = open_sock_tcp (port);
if (!soc) exit(0);

data = raw_string (0x00,0x00,0x00,0x00,0x03,0x20,0xBC,0x02);
data += crap (data:"2", length:256);
data += crap (data:"A", length:20);
data += raw_string (0x0B, 0x11, 0x0B, 0x0F, 0x03, 0x0E, 0x09, 0x0B,
                    0x16, 0x11, 0x14, 0x10, 0x11, 0x04, 0x03, 0x1C,
                    0x11, 0x1C, 0x15, 0x01, 0x00, 0x06);
data += crap (data:"A", length:402);

send (socket:soc, data:data);
ret = recv (socket:soc, length:4096);

if ((strlen(ret) == 8) && ( "0000730232320000" >< hexstr(ret) ))
{
 security_note (port:port, data:"BrightStor ARCServe UniversalAgent is running on this port");;
 set_kb_item (name:"ARCSERVE/UniversalAgent", value:TRUE);
}
