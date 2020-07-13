#
# (C) Tenable Network Security
#
if(description)
{
 script_id(15894);
 script_version("$Revision: 1.10 $");
 script_cve_id("CAN-2004-1050");
 if ( defined_func("script_xref") ) script_xref(name:"IAVA", value:"2004-A-0020");
 
 name["english"] = "Cumulative Security Update for Internet Explorer (889293)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running a version of Internet Explorer 6 SP1 which is 
vulnerable to a vulnerability which may allow an attacker to execute arbitrary
code on the remote host.

To exploit this flaw, an attacker would need to lure a victim on the remote
system into visiting a rogue website.

See http://www.microsoft.com/technet/security/bulletin/ms04-040.mspx
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for hotfix 889293";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/registry_full_access","SMB/WindowsVersion");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_hotfixes.inc");

if ( hotfix_check_sp(nt:7, win2k:5, xp:2) <= 0 ) exit(0);
if ( hotfix_missing(name:"867282.*") == 0 ) exit(0); 
if ( hotfix_missing(name:"890923.*") == 0 ) exit(0); 
if ( hotfix_missing(name:"883939.*") == 0 ) exit(0); 

port = get_kb_item("SMB/transport");
if(!port) port = 139;


version = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Internet Explorer/Version");
if (version && ereg(pattern:"^6\.0*\.2800\.1106", string:version))
{
 key = get_kb_item ("SMB/Registry/HKLM/SOFTWARE/Microsoft/Active Setup/Installed Components/{839117ee-2132-4bae-a56a-42b50204c9b9}/Version");
 if (!key)
   security_hole (port);
 else
   set_kb_item (name:"SMB/KB889293", value:TRUE);
}
