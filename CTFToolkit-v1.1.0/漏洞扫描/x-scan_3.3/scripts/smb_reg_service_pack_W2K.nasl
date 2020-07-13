#
# This script was written by Tenable Network Security
#
# This script is released under Tenable Plugins License
#

if(description)
{
 script_id(10531);
 script_bugtraq_id(7930, 8090, 8128, 8154);
 script_version ("$Revision: 1.29 $");
 script_cve_id("CAN-1999-0662");
 name["english"] = "SMB Registry : Win2k Service Pack version";
 
 script_name(english:name["english"]);
 
 desc["english"] = "

This script reads the registry
key HKLM\SOFTWARE\Microsoft\Windows NT\CSDVersion
to determine the Service Pack the host is running.

Sensitive servers should always run the latest service
pack for security reasons.

Risk factor : High
";

 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the remote SP";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("smb_reg_service_pack.nasl");
 script_require_keys("SMB/WindowsVersion","SMB/CSDVersion");
 exit(0);
}

port = get_kb_item("SMB/transport");
if(!port)port = 139;

win = get_kb_item("SMB/WindowsVersion"); 
if (!win) exit(0);

sp = get_kb_item("SMB/CSDVersion");

if(win == "5.0")
{
 if (sp)
   set_kb_item(name:"SMB/Win2K/ServicePack", value:sp);

 if((!sp) || (ereg(pattern:"Service Pack [123]",string:sp)))
 {
  report = 'The remote Windows 2000 does not have the Service Pack 4 applied.\n';
  if (sp)
    report = string(report, "(it uses ", sp, " instead)\n");
  report = string(report, 
"You should apply it to be up-to-date\n",
"Risk factor : High\n",
"Solution : go to http://www.microsoft.com/windows2000/downloads/");
  security_hole(data:report, port:port);
  exit(0);
 }
 else
 {
  report = string("The remote Windows 2000 system has ",sp," applied.\n");
  security_note (port:port, data:report);
 }
}
