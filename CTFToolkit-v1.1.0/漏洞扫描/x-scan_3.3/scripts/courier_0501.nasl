#
# (C) Tenable Network Security
#
# 


if (description) {
  script_id(18620);
  script_version("$Revision: 1.1 $");

  script_bugtraq_id(14135);
 
  name["english"] = "Courier Mail Server < 0.50.1 Remote Denial Of Service Vulnerability";
  script_name(english:name["english"]);

  desc["english"] = "
The remote host is running Courier Mail Server, an open source mail
server for Linux and Unix. 

According to its banner, the installed version of Courier is prone to
a remote denial of service vulnerability associated with Sender Policy
Framework (SPF) data lookups.  To exploit this flaw, an attacker would
need to control a DNS server and return malicious SPF records in
response to queries from the affected application. 

Solution : Upgrade to Courier 0.50.1 or greater.
Risk factor : Low";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for remote denial of service vulnerability in Courier Mail Server < 0.50.1";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"SMTP problems");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencie("find_service.nes", "smtpserver_detect.nasl");
  script_require_ports("Services/smtp", 25);
  script_exclude_keys("SMTP/wrapped");

  exit(0);
}


include("smtp_func.inc");


port = get_kb_item("Services/smtp");
if (!port) port = 25;
if (!get_port_state(port)) exit(0);
if (get_kb_item('SMTP/'+port+'/broken')) exit(0);


# Check the version number in the banner -- versions < 0.50.1 are vulnerable.
banner = get_smtp_banner(port);
if (banner && banner =~ "Courier 0\.([0-4][0-9]\.|50\.0[^0-9]*)") { 
  security_warning(port); 
}
