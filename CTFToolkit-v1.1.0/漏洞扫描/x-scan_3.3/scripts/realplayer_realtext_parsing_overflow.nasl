#
# (C) Tenable Network Security
#


if (description) {
  script_id(18558);
  script_version("$Revision: 1.3 $");
  script_cve_id("CAN-2005-1766", "CAN-2005-2052");
  script_bugtraq_id(13530, 14048, 14073);

  name["english"] = "RealPlayer / RealOne Player for Windows Multiple Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
The remote installation of RealPlayer / RealOne Player for Windows is
prone to several vulnerabilities :

  - A malicious MP3 file can be used to overwrite an arbitrary 
    file or execute an ActiveX control.

  - Using a specially-crafted RealMedia file, an attacker may 
    be able to cause a heap overflow and run arbitrary code 
    within the context of the affected application.

  - Using a specially-crafted AVI file, an attacker may 
    be able to cause a buffer overflow and run arbitrary 
    code within the context of the affected application.

  - A malicious webiste may be able to cause a local HTML
    file to be created that triggers an RM file to play
    which would then reference the local HTML file.

***** If you have already uninstalled RealPlayer, you may wish to 
***** delete the registry key at SOFTWARE\RealNetworks\RealPlayer.

See also : http://www.idefense.com/application/poi/display?id=250&type=vulnerabilities
           http://www.eeye.com/html/research/advisories/AD20050623.html
           http://www.securityfocus.com/archive/1/403535/30/0/threaded
           http://service.real.com/help/faq/security/050623_player/EN/
Solution : Upgrade according to the vendor advisory referenced above.
Risk factor : High";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for multiple vulnerabilities in RealPlayer / RealOne Player for Windows";
  script_summary(english:summary["english"]);

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencie("realplayer_6011.nasl");
  script_require_keys("SMB/RealPlayer/Version");

  exit(0);
}


ver = get_kb_item("SMB/RealPlayer/Version");
if (ver) {
  # There's a problem if the version is less than 6.0.12.1212.
  iver = split(ver, sep:'.', keep:FALSE);
  if (
    int(iver[0]) < 6 ||
    (
      int(iver[0]) == 6 &&
      int(iver[1]) == 0 && 
      (
        int(iver[2]) < 12 ||
        (int(iver[2]) == 12 && int(iver[3]) < 1212)
      )
    )
  ) security_hole(port);
}
