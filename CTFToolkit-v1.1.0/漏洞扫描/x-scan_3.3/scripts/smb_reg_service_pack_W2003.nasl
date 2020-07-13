#
# (C) Tenable Network Security
#

if(description)
{
 script_id(17662);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CAN-1999-0662");
 script_bugtraq_id(12969, 12972, 13008);
 
 name["english"] = "SMB Registry : Windows 2003 Server SP1";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running Windows 2003 Server but does not have Service
Pack 1 applied.

Solution : Install Windows 2003 SP1
See also : http://www.microsoft.com/windowsserver2003/default.mspx
Risk Factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the remote SP";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("smb_reg_service_pack.nasl");
 script_require_keys("SMB/WindowsVersion");
 script_require_ports(139, 445);
 exit(0);
}

port = get_kb_item("SMB/transport");
if(!port)port = 139;

win = get_kb_item("SMB/WindowsVersion"); 
if (!win) exit(0);

sp = get_kb_item("SMB/CSDVersion");

if(win == "5.2" )
{
 if ( ! sp ) 
 {
  report = string(
           "The remote Windows Server 2003 does not have Service Pack 1 applied.\n",
           "You should update your system by applying latest SP from Microsoft\n",
           "Solution : http://www.microsoft.com/windowsserver2003/default.mspx\n",
           "Risk factor : Medium\n");
  security_warning(data:report, port:port);
  exit(0);
 }
 else
 {
  set_kb_item(name:"SMB/Win2003/ServicePack", value:sp);
  report = string("The remote Windows XP system has ",sp," applied.\n");
  security_note(data:report, port:port);
  exit(0);
 }
}
