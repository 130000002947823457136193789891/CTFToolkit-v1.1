#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#
#  based on work from
#  (C) Tenable Network Security
#
#  Ref: Max <spamhole@gmx.at>
#
#  This script is released under the GNU GPLv2
#

if(description)
{
 script_id(15432);
 script_bugtraq_id(11166);
 script_cve_id("CAN-2004-0906");
 script_version("$Revision: 1.1 $");

 name["english"] = "Mozilla/Firefox default installation file permission flaw";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is using Mozilla and/or Firefox, an alternative web browser.

The remote version of this software is prone to an improper file permission
setting.

This flaw only exists if the browser is installed by the Mozilla Foundation
package management, thus this alert might be a false positive.

A local ttacker could overwrite arbitrary files or execute arbitrary code in
the context of the user running the browser.

Solution : Update to the latest version of the software
Risk factor : Medium";


 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the version of Mozilla/Firefox";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("mozilla_firefox_code_exec.nasl");
 exit(0);
}


moz = get_kb_item("Mozilla/Version");
if ( moz )
{
  if ( moz && ereg(pattern:"^(0\.|1\.([0-6]\.|7\.[0-2]))", string:moz) ) 
  {
   security_warning(0);
   exit(0);
  }
}


fox = get_kb_item("Mozilla/Firefox/Version");
if (fox)
{
  if (ereg(pattern:"0\.[0-9]\.", string:fox) )
     security_warning(0);
}
