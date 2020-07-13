#
# (C) Tenable Network Security
#
# 

if (description) {
  script_id(18402);
  script_version("$Revision: 1.1 $");
  script_bugtraq_id(13790);

  name["english"] = "Hummingbird ftpd Buffer Overflow Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
According to its banner, the ftpd daemon installed on the remote host
is from the Hummingbird Connectivity suite and suffers from a buffer
overflow vulnerability.  An attacker can crash the daemon and might be able to
execute code remotely within the context of the affected service. 

Solution : None at this time.
Risk factor : High";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for buffer overflow vulnerability in Hummingbird ftpd";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Gain root remotely");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencie("find_service1.nasl");
  script_require_ports("Services/ftp", 21);

  exit(0);
}


include("ftp_func.inc");


port = get_kb_item("Services/ftp");
if (!port) port = 21;
if (!get_port_state(port)) exit(0);


# Use a banner check; it's not configurable.
banner = get_ftp_banner(port:port);
if (
  banner && 
  banner =~ "^220[- ] .+HCLFTPD\) Version ([0-9]\.|10\.0\.0\.0)\)"
) security_hole(port);

