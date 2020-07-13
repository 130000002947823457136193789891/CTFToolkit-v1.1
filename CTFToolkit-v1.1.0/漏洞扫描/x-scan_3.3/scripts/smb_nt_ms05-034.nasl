#
# (C) Tenable Network Security
#


if(description)
{
 script_id(18487);
 script_version("$Revision: 1.3 $");
 script_bugtraq_id(13846, 13956, 13954);
 script_cve_id("CAN-2005-1215", "CAN-2005-1216");
 
 name["english"] = "Cumulative Update for ISA Server 2000 (899753)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing a cumulative update for ISA Server 2000 which fixes
several security flaws which may allow an attacker to elevate his privileges.

Solution : http://www.microsoft.com/technet/security/bulletin/ms05-034.mspx
Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for hotfix 899753";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/registry_full_access","SMB/WindowsVersion");
 script_require_ports(139, 445);
 exit(0);
}


if ( !get_kb_item("SMB/registry_full_access") ) exit(0);

fpc = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Fpc");
if (!fpc) exit(0);

fix = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Fpc/Hotfixes/SP1/430");
if(!fix)security_hole(port);
