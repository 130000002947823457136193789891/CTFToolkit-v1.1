#
# (C) Tenable Network Security
#

if(description)
{
 script_id(16479);
 script_version("$Revision: 1.2 $");

 script_cve_id("CAN-2005-0485");
 script_bugtraq_id(12576, 12611, 12687);
 if (defined_func("script_xref")) {
   script_xref(name:"OSVDB", value:"13931");
   script_xref(name:"OSVDB", value:"14114");
 }

 name["english"] = "paNews <= 2.0b4 Multiple Vulnerabilities";
 script_name(english:name["english"]);
 
 desc["english"] = "
According to its banner, the remote host is running a version of
paNews that suffers from the following vulnerabilities:

  o A Cross-Site-Scripting (XSS) Vulnerability.
    An attacker would need to be able to coerce an unsuspecting 
    user into visiting a malicious website.  Upon successful
    exploitation, the attacker would be able to possibly steal 
    credentials or execute browser-side code. 

  o Remote PHP Script Code Execution Vulnerability. 
    A remote attacker may be able to run arbitrary code in the 
    context of the user running the web service or to read 
    arbitrary files on the target because paNews fails to
    properly sanitize input passed to the script 
    'includes/admin_setup.php'. To exploit this flaw, the
    server must be configured to allow writes by the web user 
    to the directory 'includes' (not the default
    configuration).

  o SQL Injection Issue in the 'login' method of includes/auth.php.
    A remote attacker can leverage this vulnerability to add 
    users with arbitrary privileges.

  o Local Script Injection Vulnerability in includes/admin_setup.php.
    A user defined to the system (see above) can inject arbitrary
    PHP code into paNews' config.php via the 'comments' and 
    'autapprove' parameters of the 'admin_setup.php'
    script.

Solution : Upgrade to a newer version when available.
Risk factor : Medium";
 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for multiple vulnerabilities in paNews <= 2.0b4";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 
 script_dependencies("http_version.nasl", "panews_detect.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}


include("http_func.inc");


port = get_http_port(default:80);
if (! port) exit(0);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/panews"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];
  if (ver =~  "^([0-1]\.|2\.0b[0-4])$") security_warning(port);
}
