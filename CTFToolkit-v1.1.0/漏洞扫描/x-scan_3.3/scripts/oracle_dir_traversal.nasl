#
# (C) Tenable Network Security
#
# 

if (description) {
  script_id(17654);
  script_version("$Revision: 1.3 $");

  script_bugtraq_id(12749);

  name["english"] = "Oracle Database 8i/9i Multiple Remote Directory Traversal Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
According to its version number, the installation of Oracle on the remote
host is reportedly subject to multiple directory traversal
vulnerabilities that may allow a remote attacker to read, write, or
rename arbitrary files with the privileges of the Oracle Database
server.  An authenticated user can craft SQL queries such that they
would be able to retrieve any file on the system and potentially
retrieve and/or modify confidential data on the target's Oracle
server. 

See also : http://www.argeniss.com/research/ARGENISS-ADV-030501.txt
Solution : http://www.oracle.com/technology/deploy/security/pdf/cpu-jan-2005_advisory.pdf
Risk Factor : Medium";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for multiple remote directory traversal vulnerabilities in Oracle Database 8i/9i";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  family["english"] = "Misc.";
  script_family(english:family["english"]);

  script_dependencie("oracle_tnslsnr_version.nasl");
  script_require_ports("Services/oracle_tnslsnr");

  exit(0);
}

include('global_settings.inc');
if ( report_paranoia < 1 ) exit(0);

port = get_kb_item("Services/oracle_tnslsnr");
if (isnull(port)) exit(0);


version = get_kb_item(string("oracle_tnslsnr/", port, "/version"));
if (version) {
  if (ereg(pattern:".*Version (8\.(0\.([0-5]\.|6\.[0-3])|1\.([0-6]\.|7\.[0-4]))|9\.(0\.(0\.|1\.[0-5]|2\.[0-6]|3\.[0-1]|4\.[0-1])|2\.0\.[0-5])|10\.(0\.|1\.0\.[0-3]))", string:version)) security_hole(port);
}
