#
# This script was written by Sverre H. Huseby <shh@thathost.com>
#
# See the Nessus Scripts License for details
#

if(description)
{
  script_id(11617);
  script_version ("$Revision: 1.6 $");

  name["english"] = "Horde and IMP test disclosure";
  script_name(english:name["english"]);

  desc["english"] = "
The remote server is running Horde and/or IMP with test scripts
available from the outside.  The scripts may leak server-side
information that is valuable to an attacker.

Solution: test.php and imp/test.php should be deleted,
or they should be made unreadable by the web server.
Risk factor : Medium";

  script_description(english:desc["english"]);

  summary["english"] = "Checks if test.php is available in Horde or IMP";

  script_summary(english:summary["english"]);

  script_category(ACT_ATTACK);

  script_copyright(english:"Sverre H. Huseby");
  family["english"] = "CGI abuses";
  script_family(english:family["english"]);

  script_dependencies("horde_detect.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);


if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);

files = make_list(
  "/test.php", "/test.php3",
  "/imp/test.php", "/imp/test.php3"
);

# Test an install.
install = get_kb_item(string("www/", port, "/horde"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  d = matches[2];

  foreach f (files) {
    req = http_get(item:string(d, f), port:port);
    res = http_keepalive_send_recv(port:port, data:req);

    if (res == NULL)
      exit(0);

    if ('PHP Version' >< res
        && ('Horde Version' >< res || 'IMP Version' >< res)) {
      security_warning(port);
      exit(0);
    }
  }
}
