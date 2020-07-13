#
# This script was written by Noam Rathaus
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11988);
 script_cve_id("CVE-2003-1022");
 script_bugtraq_id(9377);
 script_version("$Revision: 1.4 $");

 name["english"] = "FSP Suite Directory Traversal Vulnerability";
 script_name(english:name["english"]);

 desc["english"] = "
The FSP Suite (daemon) has been found to improperly filter out
paths with trailing / or starting with /. This would allow an attacker
access to files that reside outside the bounding FSP root diretory.

Risk factor : High";

 script_description(english:desc["english"]);

 summary["english"] = "FSPD Detection";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2004 Noam Rathaus");
 family["english"] = "Remote file access";
 script_family(english:family["english"]);
 script_dependencie("fsp_detection.nasl");
 exit(0);
}

debug = 0;

# This is UDP based protocol ...

banners = get_kb_list("fsp/banner/*");
if ( isnull(banners) ) exit(0);

foreach k (keys(banners))
{
 port   = int(k - "fsp/banner/");
 banner = banners[k];

 if (egrep(string:banner, pattern:"fspd (2\.8\.1b1[0-7]|2\.8\.0|2\.[0-7]\.|[0-1]\.)"))
 {
  security_hole(port:port, protocol:"udp");
  exit(0);
 }
}
