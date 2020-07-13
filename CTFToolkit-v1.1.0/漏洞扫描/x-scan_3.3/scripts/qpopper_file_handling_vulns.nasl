#
# (C) Tenable Network Security
#
# 

if (description) {
  script_id(18361);
  script_version("$Revision: 1.1 $");

  script_cve_id("CAN-2005-1151", "CAN-2005-1152");
  script_bugtraq_id(13714);

  name["english"] = "Qpopper Insecure File Handling Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
According to its banner, the remote host is running a version of the
Qpopper POP3 server that suffers from two local, insecure file
handling vulnerabilities.  First, it fails to properly drop root
privileges when processing certain local files, which could lead to
overwriting or creation of arbitrary files as root.  And second, it
fails to set the process umask, potentially allowing creation of
group- or world-writeable files. 

See also : http://bugs.gentoo.org/show_bug.cgi?id=90622
Solution : Upgrade to Qpopper 4.0.5 or later.
Risk factor : Low";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for insecure file handling vulnerabilities in Qpopper";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencie("find_service.nes");
  script_require_ports("Services/pop3", 110);
  script_exclude_keys("pop3/false_pop3");

  exit(0);
}

include('global_settings.inc');

if (report_paranoia < 1) exit(0);	# FP on debian

if (get_kb_item("pop3/false_pop3")) exit(0);
port = get_kb_item("Services/pop3");
if (!port) port = 110;
if (!get_port_state(port)) exit(0);


# Read banner.
soc = open_sock_tcp(port);
if (!soc) exit(0);
s = recv_line(socket:soc, length:1024);
close(soc);
if (!strlen(s)) exit(0);


# There's a problem if the banner indicates version 4.0.4 or earlier.
if (s =~ "^\+OK QPOP \(version ([0-3]\..*|4\.0\.[0-4])$") {
  security_note(port);
}
