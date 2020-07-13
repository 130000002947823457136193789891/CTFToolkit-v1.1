#
# (C) Tenable Network Security
#
# 


if (description) {
  script_id(17985);
  script_version("$Revision: 1.2 $");
  script_bugtraq_id(13001);

  name["english"] = "CommuniGate Pro LISTS Module Denial of Service Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
According to its banner, the version of CommuniGate Pro running on the
remote host is prone to an unspecified denial of service vulnerability
arising from a flaw in the LISTS module.  An attacker may be able to
crash the server by sending a malformed multipart message to a list. 

Solution : Upgrade to CommuniGate Pro 4.3c3 or newer.
Risk factor : High";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for denial of service vulnerability in CommuniGate Pro LISTS module";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Denial of Service");
 
  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencie("find_service.nes", "global_settings.nasl", "smtpserver_detect.nasl");
  script_require_ports("Services/smtp", 25);
  script_exclude_keys("SMTP/wrapped");

  exit(0);
}


include("smtp_func.inc");


port = get_kb_item("Services/smtp");
if (!port) port = 25;
if (!get_port_state(port)) exit(0);
if (get_kb_item('SMTP/'+port+'/broken')) exit(0);


banner = get_smtp_banner(port);
if ( banner &&
    egrep(
    string:banner, 
    pattern:"CommuniGate Pro ([0-3]|4\.[0-2]|4\.3([ab][0-9]|c[0-2]))"
  )
) security_hole(port);
