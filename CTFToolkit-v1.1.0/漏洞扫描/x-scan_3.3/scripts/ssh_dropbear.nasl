#
# (C) Tenable Network Security
#

if(description)
{
 script_id(11821);
 script_bugtraq_id(8439);
 script_version ("$Revision: 1.4 $");
 
 name["english"] = "Dropbear SSH server format string vulnerability";
 script_name(english:name["english"]);
 
 desc["english"] = "There is a format string vulnerability in all versions
of the Dropbear SSH server up to and including version 0.34. An attacker
may use this flaw to execute arbitrary code on the SSH server.

Solution: Upgrade to the latest version of the Dropbear SSH server.

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks remote SSH server type and version";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "General";
 script_family(english:family["english"]);
 script_require_ports("Services/ssh", 22);
 script_dependencies("ssh_detect.nasl");
 exit(0);
}

#
# The script code starts here
#

port = get_kb_item("Services/ssh");
if (!port) port = 22;

banner = get_kb_item("SSH/banner/" + port );
if ( ! banner ) exit(0);

banner = tolower(banner);

if("dropbear" >< banner)
{
    if (ereg(pattern:"ssh-.*-dropbear_0\.(([0-2].*)|3[0-4])", string:banner))
    {
        security_hole(port);
    }
}
 
