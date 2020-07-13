#
# This script was written by Noam Rathaus <noamr@beyondsecurity.com>
# 
#
# See the Nessus Scripts License for details
#
# Author: dr_insane
# Subject: Flash Ftp server 1.0 Directory traversal
# Date: January 1, 2004
# http://packetstormsecurity.nl/0401-exploits/Flash.txt
# http://www.secunia.co.uk/advisories/10522/

if(description)
{
 script_id(11978);
 script_version("$Revision: 1.3 $");
 
 name["english"] = "Flash FTP Server Directory Traversal Vulnerability";
 
 script_name(english:name["english"]);
             
 desc["english"] = "
Flash FTP Server easy-to-set-up FTP server for all Windows platforms.
Some bugs were found that will allow a malicious user to write and 
read anywhere on the disk.

Solution : Upgrade to the latest version of this software
Risk factor : High";
                 
 script_description(english:desc["english"]);
 
 script_summary(english:"Checks if the version Flash FTP Server");
 script_category(ACT_GATHER_INFO);
 script_family(english:"FTP");

 
 script_copyright(english:"This script is Copyright (C) 2004 Noam Rathaus");
                  
 script_dependencie("find_service.nes");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here : 
#

include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if(!port)port = 21;

banner = get_ftp_banner(port:port);
if ( ! banner ) exit(0);

if(egrep(pattern:"^220 Flash FTP Server v(1\.|2\.[0-1]) ready", string:banner))security_hole(port);

