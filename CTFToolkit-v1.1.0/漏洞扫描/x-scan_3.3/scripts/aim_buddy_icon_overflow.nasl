#
# (C) Tenable Network Security
#
# 

if (description) {
  script_id(18432);
  script_version("$Revision: 1.2 $");

  script_cve_id("CAN-2005-1891");
  script_bugtraq_id(13880);

  name["english"] = "AIM Buddy Icon Overflow Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
According to its banner, the remote host is running a version of AOL
Instant Messanger that has is prone to an integer overflow in its GIF
parser, 'ateimg32.dll'.  Using a specially-crafted GIF file as a buddy
icon, an attacker can cause a crash of the affected AIM client and
potentially even execute arbitrary code remotely. 

See also : http://www.security-protocols.com/modules.php?name=News&file=article&sid=2748
Solution : Unknown at this time.
Risk factor : Low";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for buddy icon overflow vulnerability in AIM";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencies("aim_detect.nasl");
  script_require_keys("AIM/version");

  exit(0);
}


# Test an install.
ver = get_kb_item("AIM/version");
if (ver) {
  # There's a problem if the newest version is 5.9.3797 or below.
  iver = split(ver, sep:'.', keep:FALSE);
  if (
    int(iver[0]) < 5 ||
    (
      int(iver[0]) == 5 && 
      (
        int(iver[1]) < 9 ||
        (int(iver[1]) == 9 && int(iver[2]) <= 3797)
      )
    )
  ) security_warning(port);
}
