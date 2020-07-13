#
# (C) Tenable Network Security
#
# 

if (description) {
  script_id(18034);
  script_version("$Revision: 1.6 $");

  script_bugtraq_id(13145, 13144, 13139, 13238, 13236, 13235, 13234, 13239);

  name["english"] = "Oracle Database Multiple Remote Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
According to its version number, the installation of Oracle on the remote
host is reportedly subject to multiple unspecified vulnerabilities.
Some vulnerabilities don't require authentication. It may allow an attacker
to craft SQL queries such that they would be able to retrieve any file on 
the system and potentially retrieve and/or modify confidential data on the
target's Oracle server. 

Solution : http://www.oracle.com/technology/deploy/security/pdf/cpuapr2005.pdf
Risk Factor : High";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for multiple remote vulnerabilities in Oracle Database";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  family["english"] = "Misc.";
  script_family(english:family["english"]);

  script_dependencie("oracle_tnslsnr_version.nasl");
  script_require_ports("Services/oracle_tnslsnr");

  exit(0);
}

#broken
exit (0);

port = get_kb_item("Services/oracle_tnslsnr");
if (isnull(port)) exit(0);


version = get_kb_item(string("oracle_tnslsnr/", port, "/version"));
if (version) {
  if (ereg(pattern:".*Version (8\.(0\.|1\.([0-6]\.|7\.[0-4]))|9\.(0\.(0\.|1\.[0-5]|2\.[0-6]|3\.[0-1]|4\.[0-1])|2\.0\.[0-6])|10\.(0\.|1\.0\.[0-4])|11\.([0-4]\.|5\.[0-9][^0-9]))", string:version)) security_hole(port);
}
