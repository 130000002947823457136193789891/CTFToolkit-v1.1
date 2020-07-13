#
# (C) Tenable Network Security
#
# 

if (description) {
  script_id(18141);
  script_version("$Revision: 1.2 $");

  name["english"] = "Xerox WorkCentre Device Detection";
  script_name(english:name["english"]);
 
  desc["english"] = "
This script detects whether the remote host is a Xerox WorkCentre device
and, if so, extracts its model number and the System Software as well as
the Net Controller Software versions.";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for Xerox WorkCentre devices";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencie("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
banner = get_http_banner(port:port);
if (!banner || "Xerox_MicroServer" >!< banner) exit(0);


# Try to get the model number (Properties, Description).
req = http_get(item:"/properties/description.dhtml", port:port);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
if (res == NULL) exit(0);

# Examples:
#   '			Xerox WorkCentre Pro 55, v1 Multifunction System '
#   '			Xerox WorkCentre Pro 35, v1 Multifunction System'
#   '                        Xerox WorkCentre Pro 32C, v1 Multifunction System'
#   '			WorkCentre PE120 Series '
pat = "^ +(Xerox )?WorkCentre ([^,]+)";
matches = egrep(pattern:pat, string:res);
foreach match (split(matches)) {
  match = chomp(match);
  model = eregmatch(pattern:pat, string:match);
  if (!isnull(model)) {
    model = model[1];
    break;
  }
}
if (isnull(model)) exit(0);


# Now try to get the System Software and Net Controller Software versions 
# from the configuration page (Properties, General Setup, Configuration).
#
# nb: these are normally calculated by Javascript. :-(
req = http_get(item:"/properties/configuration.dhtml", port:port);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
if (res == NULL) exit(0);

# Examples:
#   'var versions     = "Xerox, 8.60.0, Imaging Input Terminal;Xerox, 0.1.2.59, Software Compatibility Database;";'
pat = "var versions .+, ([^,]+), Software Compatibility Database";
matches = egrep(pattern:pat, string:res);
foreach match (split(matches)) {
  match = chomp(match);
  scd = eregmatch(pattern:pat, string:match);
  if (!isnull(scd)) {
    scd = scd[1];
    break;
  }
}
if (isnull(scd)) scd = "unknown";

# Examples:
#   'var SysDescrip = "Xerox WorkCentre Pro Multifunction System, ESS 0.R01.02.329.01, IOT 23.16.0, UI 0.2.84.14, Finisher 9.15.0, Scanner 15.7.0;";'
#   'var SysDescrip = "Xerox WorkCentre Pro Multifunction System, ESS 0.S01.02.058.04, IOT 13.0.0, UI 0.1.2.59, Scanner 8.60.0;";'
pat = "var SysDescrip .+ ESS ...([^,]+),";
matches = egrep(pattern:pat, string:res);
foreach match (split(matches)) {
  match = chomp(match);
  ess = eregmatch(pattern:pat, string:match);
  if (!isnull(ess)) {
    ess = ess[1];
    break;
  }
}
# If that didn't work...
if (isnull(ess)) {
  # It may be two lines after the label 'Engine', as occurs with
  # PE120 Series devices.
  i = 0;
  lines = split(res, keep:FALSE);
  foreach line (lines) {
    if (line =~ "^ +Engine:$") {
        ess = lines[i+2];
        break;
    }
    ++i;
  }
}
if (isnull(ess)) ess = "unknown";


# Update KB and report findings.
set_kb_item(
  name:string("www/", port, "/workcentre"),
  value:string(model, ", SCD ", scd, ", ESS ", ess)
);

desc = string(
  "The remote host appears to be a Xerox WorkCentre device:\n",
  "\n",
  "  Model:                           ", model, "\n",
  "  System Software version:         ", scd, "\n",
  "  Net Controller Software version: ", ess, "\n"
);
security_note(port:port, data:desc);
