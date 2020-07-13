#
# (C) Tenable Network Security
#
# 

if (description) {
  script_id(18208);
  script_version("$Revision: 1.1 $");

  name["english"] = "602LAN SUITE Open Telnet Proxy";
  script_name(english:name["english"]);
 
  desc["english"] = "
The remote host is running 602LAN SUITE with an open Telnet server
proxy.  By using through such a proxy, an attacker is able to launch
attacks that appear to originate from the remote host and possibly to
access resources that are only available to machines on the same
internal network as the remote host. 

Solution : Reconfigure 602LAN SUITE, disabling the TELNET server proxy.
Risk factor : High";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for telnet proxy in 602LAN SUITE";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencie("find_service.nes");
  script_require_ports("Services/telnet", 23);

  exit(0);
}


port = get_kb_item("Services/telnet");
if (!port) port = 23;
if (!get_port_state(port)) exit(0);


# Open a connection and grab the banner.
soc = open_sock_tcp(port);
if (!soc) exit(0);
banner = recv(socket:soc, length:2048);


# If it looks like 602LAN SUITE...
if ("host[:port]:" >< banner) {
  # Try to connect back to the server on port 31337.
  req = string(this_host(),":31337\r\n");
  filter = string("tcp and src ", get_host_ip(), " and dst ", this_host(), " and dst port 31337");
  send(socket:soc, data:req);
  res = recv_line(socket:soc, length:2048);

  # Hmmm, there seems to be a filter limiting outbound connections.
  if ("Access Denied by IP Filter" >< res) exit(0);

  # If we can, there's a problem.
  res = pcap_next(pcap_filter:filter);
  if (res) security_hole(port);
}
