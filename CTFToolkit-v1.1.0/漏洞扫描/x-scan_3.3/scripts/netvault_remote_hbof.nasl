#
# (C) Tenable Network Security
#
# 

if (description) {
  script_id(18257);
  script_version("$Revision: 1.3 $");

  script_cve_id("CAN-2005-1009");
  script_bugtraq_id(12967, 13594, 13618);

  name["english"] = "BakBone NetVault Remote Heap Overflow Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
The installed version of BakBone NetVault on the remote host suffers
from two remote heap buffer overflow vulnerabilities.  An attacker may
be able to exploit this flaw and execute arbitrary code with SYSTEM
privileges on the affected machine. 

See also : http://www.hat-squad.com/en/000164.html
           http://www.securityfocus.com/data/vulnerabilities/exploits/netvault_hof.c
Solution : Filter access to TCP and UDP port 20031 on this host.
Risk factor : High";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for remote heap overflow vulnerabilities in BakBone NetVault";
  script_summary(english:summary["english"]);

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gain a shell remotely");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencie("find_service2.nasl");
  script_require_ports("Services/unknown", 20031);

  exit(0);
}


include("misc_func.inc");


if ( safe_checks() )
{
port = get_kb_item("Services/unknown");
if (!port) port = 20031;
if (known_service(port:port)) exit(0);
}
else port = 20031;

if (!get_port_state(port)) exit(0);


# Connect to the port and send an initial packet.
soc = open_sock_tcp(port);
if (!soc) exit(0);

grabcpname = 
  raw_string(
    0xC9, 0x00, 0x00, 0x00, 0x01, 0xCB, 0x22, 0x77,
    0xC9, 0x17, 0x00, 0x00, 0x00, 0x69, 0x3B, 0x69,
    0x3B, 0x69, 0x3B, 0x69, 0x3B, 0x69, 0x3B, 0x69, 
    0x3B, 0x69, 0x3B, 0x69, 0x3B, 0x69, 0x3B, 0x69, 
    0x3B, 0x73, 0x3B, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00,
    0x03, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x0B, 0x00, 0x00, 0x00
  ) +
  crap(data:raw_string(0x90), length:10) +
  crap(data:raw_string(0x00), length:102) +
  raw_string(0x09) +
  crap(data:raw_string(0x00), length:8);
send(socket:soc, data:grabcpname);
res = recv(socket:soc, length:1024);
close(soc);
if (res == NULL) exit(0);
len = strlen(res);


# If the response packet looks like it's from NetVault...
if (len >= 400 && ord(res[13]) == 105 && ord(res[14]) == 59) {
  # Get the version number of NetVault on the remote.
  ver = string(res[len-37], ".", res[len-35], ".", res[len-34]);

  if (ver =~ "^(6\.|7\.[0-3]\.)") security_hole(port);
}
