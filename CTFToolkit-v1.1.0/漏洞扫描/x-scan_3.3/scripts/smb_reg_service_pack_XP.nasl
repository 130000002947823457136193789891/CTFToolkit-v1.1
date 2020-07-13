#
# This script was written by Georges Dagousset <georges.dagousset@alert4web.com>
# Modified by David Maciejak <david dot maciejak at kyxar dot fr> to add check for Service Pack 2
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11119);
 script_bugtraq_id(10897, 11202);
 script_version ("$Revision: 1.11 $");
 script_cve_id("CAN-1999-0662");
 
 name["english"] = "SMB Registry : XP Service Pack version";
 name["francais"] = "Obtention du numéro du service pack de XP par SMB";
 
 script_name(english:name["english"],
 	     francais:name["francais"]);
 
 desc["english"] = "
This script reads the registry key HKLM\SOFTWARE\Microsoft\Windows NT\CSDVersion
to determine the Service Pack the host is running.

Sensitive servers should always run the latest service pack for security reasons.
Risk factor : High 
";

 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the remote SP";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2002 Alert4Web.com");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("smb_reg_service_pack.nasl");
 script_require_keys("SMB/WindowsVersion");
 script_require_ports(139, 445);
 exit(0);
}

if ( get_kb_item("SMB/RegOverSSH") ) exit(0);

port = get_kb_item("SMB/transport");
if(!port)port = 139;

win = get_kb_item("SMB/WindowsVersion"); 
if (!win) exit(0);

sp = get_kb_item("SMB/CSDVersion");

if(win == "5.1")
{
 if (sp)
   set_kb_item(name:"SMB/WinXP/ServicePack", value:sp);
 else
 {
  report = string(
           "The remote Windows XP has no Service Pack applied.\n",
           "You should update your system by applying latest SP from Microsoft\n",
           "Risk factor : High\n",
           "Solution : go to http://www.microsoft.com/windowsxp/");
  security_hole(data:report, port:port);
  exit(0);
 }

 if (sp == "Service Pack 2")
 {
  report = string("The remote Windows XP system has ",sp," applied.\n");
  security_note(data:report, port:port);
  exit(0);
 }
 
 if(sp == "Service Pack 1")
 {
  report = string(
           "The remote Windows XP has Service Pack 1 applied but does not have Service Pack 2.\n",
           "You should apply it to be up-to-date.\n",
           "Risk factor : High\n",
           "Solution : go to http://www.microsoft.com/windowsxp/");
  security_hole(data:report, port:port);
  exit(0);
 }
}
