#
# (C) Tenable Network Security
#
# 

if (description) {
  script_id(18246);
  script_version("$Revision: 1.2 $");

  script_cve_id("CAN-2005-1650", "CAN-2005-1651", "CAN-2005-1652", "CAN-2005-1653");
  script_bugtraq_id(13597);

  name["english"] = "Woppoware PostMaster <= 4.2.2 Multiple Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
According to its banner, the version of Woppoware Postmaster on the
remote host suffers from multiple vulnerabilities:

  - An Authentication Bypass Vulnerability
    An attacker can bypass authentication by supplying an
    account name to the 'email' parameter of the
    'message.htm' page. After this, the attacker can read
    existing messages, compose new messages, etc as the
    specified user.

  - Information Disclosure Vulnerabilities
    The application responds with different messages based
    on whether or not an entered username is valid. It 
    also fails to sanitize the 'wmm' parameter used in
    'message.htm', which could be exploited to conduct
    directory traversal attacks and retrieve arbitrary
    files from the remote host.

  - A Cross-Site Scripting Vulnerability
    The 'email' parameter of the 'message.htm' page is
    not sanitized of malicious input before use.

Solution : Reconfigure Woppoware Postmaster, disabling the webmail service.
Risk factor : High";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for multiple vulnerabilities in Woppoware PostMaster <= 4.2.2";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencie("find_service.nes");
  script_require_ports("Services/www", 8000);

  exit(0);
}


include("http_func.inc");


port = get_http_port(default:8000);
if (!get_port_state(port)) exit(0);


# Check the banner.
banner = get_http_banner(port:port);
if (
  banner && 
  banner =~ "^Server: PostMaster ([0-3]\.|4\.([0-1]\.|2\.[0-2][^0-9]))"
) security_hole(port);
