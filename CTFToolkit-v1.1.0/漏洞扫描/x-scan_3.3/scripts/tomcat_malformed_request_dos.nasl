#
# (C) Tenable Network Security
#
# 

  desc["english"] = "
The installed version of Apache TomCat on the remote host suffers from
a denial of service vulnerability due to its failure to handle
malformed requests.  By submitting a specially crafted request, an
attacker can cause Tomcat to stop responding to further requests.  At
present, details on the specific nature of such requests are not
generally known. 

Solution : Upgrade to Apache Tomcat version 5.x.

Risk factor : High";


if (description) {
  script_id(17322);
  script_version("$Revision: 1.3 $");

  script_cve_id("CAN-2005-0808");
  script_bugtraq_id(12795);

  name["english"] = "Apache Tomcat Remote Malformed Request Denial Of Service Vulnerability";
  script_name(english:name["english"]);
 
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for remote malformed request denial of service vulnerability in Apache Tomcat";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  family["english"] = "Denial of Service";
  script_family(english:family["english"]);

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencie("http_version.nasl");
  script_require_ports("Services/http", 80);

  exit(0);
}

include ('http_func.inc');

port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);


banner = get_http_banner(port:port);
if (banner &&
    egrep(string:banner, pattern:"^Server: (Apache )?Tomcat( Web Server)?/([12]\..*|3\.(0\.0|1\.[01]|2\.[0-4]|3\.[01]))")
  ) {
    desc = str_replace(
      string:desc["english"],
      find:"Solution :",
      replace:string(
        "***** Nessus has determined the vulnerability exists on the target\n",
        "***** simply by looking at the version number of Apache Tomcat\n",
        "***** installed there.\n",
        "\n",
        "Solution :"
      )
    );
    security_hole(port:port, data:desc);
  }


