#
# (C) Tenable Network Security
#
# 

if (description) {
  script_id(18267);
  script_version("$Revision: 1.1 $");

  script_bugtraq_id(12787);

  name["english"] = "Xerox WorkCentre Multi-Page Document Information Disclosure Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
According to its model number and software versions, the remote host
is a Xerox WorkCentre device that may, under rare conditions, send a
fax or scan to a different addressee than intended.  This occurs only
when faxing (not copying) a multi-page document and a power failure
occurs while scanning the second page and then only if a user operates
either the fax or copy function for more than 9,999 times.  It is not
known from where the alternate addressee is derived. 

See also : http://www.xerox.com/downloads/usa/en/c/CERT_Xerox_Security_XRX05_002.pdf
Solution : Contact the Xerox Welcome Center and request software version 1.02.
Risk factor : Low";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for multi-page document information disclosure vulnerability in Xerox WorkCentre devices";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencie("xerox_workcentre_detect.nasl");

  exit(0);
}


# This function returns TRUE if the version string ver lies in
# the range [low, high].
function ver_inrange(ver, low, high) {
  local_var ver_parts, low_parts, high_parts, p, low_p, high_p;

  if (isnull(ver) || isnull(low) || isnull(high)) return FALSE;

  # Split levels into parts.
  ver_parts = split(ver, sep:".", keep:0);
  low_parts = split(low, sep:".", keep:0);
  high_parts = split(high, sep:".", keep:0);

  # Compare each part.
  i = 0;
  while (ver_parts[i] != NULL) {
    p = int(ver_parts[i]);
    low_p = int(low_parts[i]);
    if (low_p == NULL) low_p = 0;
    high_p = int(high_parts[i]);
    if (high_p == NULL) high_p = 0;

    if (p > low_p && p < high_p) return TRUE;
    if (p < low_p || p > high_p) return FALSE;
    ++i;
  }
  return TRUE;
}


# Check whether the device is vulnerable.
device = get_kb_item(string("www/", port, "/workcentre"));
if (device) {
  matches = eregmatch(string:device, pattern:"^(.+), SCD (.*), ESS (.*)$");
  if (isnull(matches)) exit(0);

  model = matches[1];
  scd = matches[2];
  ess = matches[3];

  # Test model number and software version against those in Xerox's 
  # Security Bulletin XRX 05-002.
  if (
    model =~ "M24" && 
    (
      # nb: since the bulletin only talks of the version number 
      #     but doesn't specify which, we'll check both.
      ver_inrange(ver:ess, low:"0", high:"1.01") ||
      ver_inrange(ver:scd, low:"0", high:"1.01")
    )
  ) security_warning(port);
}
