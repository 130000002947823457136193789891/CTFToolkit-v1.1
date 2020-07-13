#
# (C) Tenable Network Security
#
if(description)
{
 script_id(18028);
 script_version("$Revision: 1.5 $");
 script_cve_id("CAN-2005-0048", "CAN-2004-0790", "CAN-2004-1060", "CAN-2004-0230", "CAN-2005-0688");
 script_bugtraq_id(13124, 13116);

 name["english"] = "Vulnerabilities in TCP/IP Could Allow Remote Code Execution (network check)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host runs a version of Windows which has a flaw in its TCP/IP
stack.

The flaw may allow an attacker to execute arbitrary code with SYSTEM
privileges on the remote host, or to perform a denial of service attack
against the remote host.

Solution : http://www.microsoft.com/technet/security/bulletin/ms05-019.mspx
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for Microsoft Hotfix KB893066 (network check)";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("tcp_seq_window.nasl", "smb_nativelanman.nasl", "netbios_name_get.nasl");
 script_require_keys("TCP/seq_window_flaw", "Host/OS/smb");
 exit(0);
}

os = get_kb_item ("Host/OS/smb") ;
if ( ! os || "Windows" >!< os || "Windows 4.0" >< os ) exit(0);

if (get_kb_item("TCP/seq_window_flaw"))
 security_hole(get_kb_item("SMB/transport"));
