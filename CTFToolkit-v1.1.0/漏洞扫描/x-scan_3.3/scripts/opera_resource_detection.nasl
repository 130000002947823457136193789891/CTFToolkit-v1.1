#
# (C) Tenable Network Security
#
if(description)
{
 script_id(14346);
 script_bugtraq_id(10961, 11883);
 
 script_version("$Revision: 1.5 $");

 name["english"] = "Opera Resource Detection"; 

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is using Opera - an alternative web browser.

This version contains a flaw that allows an attacker to determine the
existence of files and directories on the remote host.

To exploit this flaw, an attacker would need to set up a rogue website
and lure a user of the remote host into visiting it with Opera. 

Solution : Install Opera 7.54 or newer.
Risk factor : Low";



 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the version of Opera.exe";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("opera_multiple_flaws.nasl");
 script_require_keys("Host/Windows/Opera/Version");
 exit(0);
}

v = get_kb_item("Host/Windows/Opera/Version");
if(strlen(v))
{
  v2 = split(v, sep:'.', keep:FALSE);
  if(int(v2[0]) < 7 || (int(v2[0]) == 7 && int(v2[1]) < 54))security_warning(port);
}


