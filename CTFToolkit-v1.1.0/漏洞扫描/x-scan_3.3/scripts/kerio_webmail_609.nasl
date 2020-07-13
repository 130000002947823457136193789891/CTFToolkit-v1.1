#
# (C) Tenable Network Security
#
# 

if (description) {
  script_id(18058);
  script_version("$Revision: 1.1 $");

  script_bugtraq_id(13180);

  name["english"] = "Kerio MailServer < 6.0.9";
  script_name(english:name["english"]);
 
  desc["english"] = "
According to its banner, the remote host is running a version of Kerio
MailServer prior to 6.0.9.  Such versions may be subject to hangs or
high CPU usage when malformed email messages are viewed through its
WebMail component.  An attacker may be able leverage this issue to deny
service to legitimate users simply by sending a specially-crafted
message to be viewed by someone using Kerio WebMail. 

Solution : Upgrade to Kerio MailServer 6.0.9 or newer.
Risk factor : High";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for Kerio MailServer < 6.0.9";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Denial of Service");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencie("find_service.nes", "http_version.nasl");
  script_require_ports("Services/smtp", 25, "Services/www", 80);

  exit(0);
}


include("smtp_func.inc");
include("http_func.inc");
include("http_keepalive.inc");


# Try to get the web server's banner.
port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
banner = get_http_banner(port:port);
# nb: anything below 6.0.9 may be vulnerable.
if (banner && banner =~ "^Server: Kerio MailServer ([0-5].*|6\.0\.[0-8])") {
  security_hole(port);
}


# If that failed, try to get the version from the SMTP server.
port = get_kb_item("Services/smtp");
if (!port) port = 25;
banner = get_smtp_banner(port:port);
if (banner && banner =~ "^220 .* Kerio MailServer ([0-5].*|6\.0\.[0-8]) ESMTP ready") {
  security_hole(port);
}
