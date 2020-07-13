#
# (C) Tenable Network Security
#
# 

if (description) {
  script_id(18374);
  script_version("$Revision: 1.3 $");

  script_cve_id("CAN-2005-1773");
  script_bugtraq_id(13768);

  name["english"] = "Listserv < 14.3-2005a Multiple Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
According to its version number, the Listserv web interface on the
remote host suffers from several critical and as-yet unspecified
vulnerabilities.  An attacker may be able to exploit these flaws to
execute arbitrary code on the affected system or allow remote denial
of service. 

See also : http://peach.ease.lsoft.com/scripts/wa.exe?A2=ind0505&L=lstsrv-l&T=0&F=&S=&P=4620
Solution : Apply the 2005a level set from LSoft.
Risk factor: High";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for multiple vulnerabilities in Listserv < 14.3-2005a";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
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


# For each CGI directory...
foreach dir (cgi_dirs()) {
  # For each of the possible names for the web interface...
  foreach wa (make_list("wa", "wa.exe", "wa.cgi")) {
    # Try to get the version number of the web interface.
    req = http_get(item:string(dir, "/", wa, "?DEBUG-SHOW-VERSION"), port:port);
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);

    # nb: WA version 2.3.31 corrects the flaw.
    if (res =~ "WA version ([01]\.|2\.([0-2]\.|3\.([0-2]|30)))") {
      security_hole(port);
      exit(0);
    }
  }
}
