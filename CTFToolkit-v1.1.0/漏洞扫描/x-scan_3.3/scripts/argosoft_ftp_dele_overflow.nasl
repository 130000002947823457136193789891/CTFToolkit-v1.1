#
# (C) Tenable Network Security
#
# 

if (description) {
  script_id(17303);
  script_version("$Revision: 1.1 $");

  script_cve_id("CAN-2005-0696");
  script_bugtraq_id(12755);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"14611");
  }
 
  name["english"] = "ArGoSoft FTP Server DELE Command Remote Buffer Overrun Vulnerability";
  script_name(english:name["english"]);

  desc["english"] = "
According to its banner, the remote host is running a version of
ArGoSoft FTP Server that is subject to a buffer overflow associated
with the DELE command.  Specifically, a malicious user with delete
rights who issues a DELE command with an argument exceeding 2000
characters can crash the service and potentially execute arbitrary
code. 

Solution : Upgrade to a version greater than ArGoSoft FTP 1.4.2.8 when
it becomes available. 

Risk factor : High";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for DELE command remote buffer overrun in ArGoSoft FTP Server";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  family["english"] = "FTP";
  script_family(english:family["english"]);

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencie("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  exit(0);
}


include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if (!port) port = 21;
if (!get_port_state(port)) exit(0);

banner = get_ftp_banner(port:port);
if (!banner) exit(0);

if (egrep(pattern:"^220 ArGoSoft FTP Server.*Version.*\(1\.([0-3]\.*|4\.[0-1]|4\.2\.[0-8])", string:banner)) security_hole(port);



