#
# (C) Tenable Network Security
#

if (description) {
  script_id(17337);
  script_version ("$Revision: 1.1 $");
  script_bugtraq_id (12812);

  name["english"] = "IBM WebSphere Application Server Remote Information Disclosure Vulnerability";
  script_name(english:name["english"]);

  desc["english"] = "
The remote host is running a version of IBM WebSphere Application that
may allow an attacker to conduct a brute-force password attack against
users who have recently had their passwords reset in WebSphere
Commerce. 

See also : http://www-1.ibm.com/support/docview.wss?uid=swg21199839

Solution : Apply WebSphere Commerce 5.6.0.2 fix pack or later.  If you
are running WebSphere Commerce v5.5 contact IBM product support and
request APAR IY60949. 

Risk Factor : Low";
  script_description(english:desc["english"]);

  summary["english"] = "Checks for remote information disclosure vulnerability in IBM WebSphere Application Server";
  script_summary(english:summary["english"]);

  script_category(ACT_GATHER_INFO);
  family["english"] = "CGI abuses";
  script_family(english:family["english"]);

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencie("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);


# Due to the nature of this vulnerability, we can only test based
# on the banner.
banner = get_http_banner(port:port);
if (
  banner &&
  egrep(string:banner, pattern:"^Server: WebSphere Application Server/([0-4]\..*|5\.([0-4]\..*|[56]\.0))")
) {
  # Check for the password reset form.
  dirs = make_list(
    "",
    "/webapp"
  );
  foreach dir (dirs) {
    req = http_get(item:string(dir, "/commerce/servlet/emp/standard/passwordResetRequest.jsp"), port:port);
    res = http_keepalive_send_recv(port:port, data:req);
    if (res == NULL) exit(0);

    # If it's available, there's a problem.
    if (tolower('name="logonId"') >< tolower(res)) {
      security_warning(port);
      exit(0);
    }
  }
}
