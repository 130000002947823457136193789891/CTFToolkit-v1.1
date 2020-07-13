#
# (C) Tenable Network Security
#

if(description)
{
 script_id(18025);
 script_cve_id("CAN-2005-0562");
 script_bugtraq_id(13114);

 script_version("$Revision: 1.2 $");

 name["english"] = "Vulnerability in MSN Messenger Could Lead to Remote Code Execution";

 script_name(english:name["english"]);

 desc["english"] = "
The remote host is running MSN Messenger.

The version of MSN Messenger used on the remote host is vulnerable
to a remote code execution vulnerability which may let an attacker
execute arbitrary code on the remote host.

Solution : http://www.microsoft.com/technet/security/bulletin/ms05-022.mspx
Risk factor : High";


 script_description(english:desc["english"]);

 summary["english"] = "Checks for MS05-022";

 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);

 script_dependencies("smb_nt_ms04-010.nasl");
 exit(0);
}


version =  get_kb_item("SMB/Registry/HKLM/SOFTWARE/Classes/Installer/Products/C838BEBA7A1AD5C47B1EB83441062011/Version");
if ( ! version ) exit(0);

 # Versions < 6.2 are affected
 if (egrep(string:version, pattern:"^602")) {
	# Fixed in 60200d0
       if (egrep(string:version, pattern:"^60200([0-9a-c])")) security_hole(port);
    }    
