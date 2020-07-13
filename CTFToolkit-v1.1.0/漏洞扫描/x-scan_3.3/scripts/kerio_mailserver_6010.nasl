#
# (C) Tenable Network Security
#
# 

if (description) {
  script_id(18256);
  script_version("$Revision: 1.1 $");

  script_bugtraq_id(13616);

  name["english"] = "Kerio MailServer < 6.0.10";
  script_name(english:name["english"]);
 
  desc["english"] = "
According to its banner, the remote host is running a version of Kerio
MailServer prior to 6.0.10.  Such versions are affected by multiple
remote denial of service vulnerabilities:

  - A crash can occur when downloading certain email messages
    in IMAP or Outlook with Kerio Outlook Connector (KOC).

  - A crash is possible under Linux when parsing email 
    messages with multiple embedded .eml attachments.

Solution : Upgrade to Kerio MailServer 6.0.10 or newer.
Risk factor : Medium";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for Kerio MailServer < 6.0.10";
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


# Try to get the web server's banner.
port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
banner = get_http_banner(port:port);
if (
  banner && 
  banner =~ "^Server: Kerio MailServer ([0-5].*|6\.0\.[0-9][^0-9]?)"
) {
  security_warning(port);
}


# If that failed, try to get the version from the SMTP server.
port = get_kb_item("Services/smtp");
if (!port) port = 25;
banner = get_smtp_banner(port:port);
if (
  banner && 
  banner =~ "^220 .* Kerio MailServer ([0-5].*|6\.0\.[0-9][^0-9]?)"
) {
  security_warning(port);
}

