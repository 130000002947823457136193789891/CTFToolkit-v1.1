#
# (C) Tenable Network Security
#
# 

if (description) {
  script_id(18419);
  script_version("$Revision: 1.2 $");

  script_cve_id("CAN-2005-1822", "CAN-2005-1823");
  script_bugtraq_id(13817);

  name["english"] = "X-Cart Multiple Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
The remote host is running X-Cart, a PHP-based shopping cart system.

The version installed on the remote host suffers from numerous SQL
injection and cross-site scripting vulnerabilities.  Attackers can
exploit the former to influence database queries,resulting possibly in a
compromise of the affected application, disclosure of sensitive data, or
even attacks against the underlying database.  and exploitation of the
cross-site scripting flaws can be used to steal cookie-based
authentication credentials and perform similar attacks. 

See also : http://www.securityfocus.com/archive/1/401035/30/0/threaded
Solution : Unknown at this time.
Risk factor : Medium";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for multiple vulnerabilities in X-Cart";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencie("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# For each CGI directory...
foreach dir (cgi_dirs()) {
  # Try to exploit one of the SQL flaws.
  req = http_get(
    item:string(dir, "/help.php?section='", SCRIPT_NAME),
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
  if (res == NULL) exit(0);

  # If ...
  if (
    # it looks like X-Cart and...
    egrep(string:res, pattern:"^Set-Cookie: xid=") &&
    egrep(string:res, pattern:"^<!-- /?central space -->") &&
    # we get a syntax error.
    egrep(string:res, pattern:string("SELECT pageid FROM xcart_stats_pages WHERE page='/cart/help\.php\?section='", SCRIPT_NAME))
  ) {
    security_warning(port);
    exit(0);
  }
}
