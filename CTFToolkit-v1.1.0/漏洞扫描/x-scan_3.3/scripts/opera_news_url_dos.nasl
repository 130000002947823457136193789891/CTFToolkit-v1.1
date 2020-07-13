#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from
# (C) Tenable Network Security
#
# Ref: David F. Madrid <conde0@telefonica.net>
# This script is released under the GNU GPLv2

if(description)
{
 script_id(14249);
 script_bugtraq_id(7430);
 
 script_version("$Revision: 1.4 $");

 name["english"] = "Opera web browser news url denial of service vulnerability";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is using Opera - an alternative web browser.

This version reportedly occurs when processing a 'news:' URL 
of excessive length, that may result in a denial of service.
It has been reported that this issue will trigger a condition 
that will prevent Opera from functioning until the program 
has been reinstalled. 


Solution : Install Opera 7.20 or newer.
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the version of Opera.exe";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("opera_multiple_flaws.nasl");
 script_require_keys("Host/Windows/Opera/Version");
 exit(0);
}

v = get_kb_item("Host/Windows/Opera/Version");
if(strlen(v))
{
  report = "
We have determined that you are running Opera v." + v + ". 

This version reportedly occurs when processing a 'news:' URL 
of excessive length, that may result in a denial of service.
It has been reported that this issue will trigger a condition 
that will prevent Opera from functioning until the program 
has been reinstalled. 


Solution : Upgrade to version 7.20 or newer
Risk factor : High";

  v2 = split(v, sep:'.', keep:FALSE);
  if(int(v2[0]) < 7 || (int(v2[0]) == 7 && int(v2[1]) < 20))security_hole(port:port, data:report);
}
