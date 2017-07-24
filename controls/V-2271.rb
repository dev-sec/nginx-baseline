# encoding: utf-8
#
=begin
-----------------
Benchmark: APACHE SERVER 2.2 for Unix
Status: Accepted

All directives specified in this STIG must be specifically set (i.e. the
server is not allowed to revert to programmed defaults for these directives).
Included files should be reviewed if they are used. Procedures for reviewing
included files are included in the overview document. The use of .htaccess
files are not authorized for use according to the STIG. However, if they are
used, there are procedures for reviewing them in the overview document. The
Web Policy STIG should be used in addition to the Apache Site and Server STIGs
in order to do a comprehensive web server review.

Release Date: 2015-08-28
Version: 1
Publisher: DISA
Source: STIG.DOD.MIL
uri: http://iase.disa.mil
-----------------
=end

CGIMONITORINGSOFTWARE = attribute(
  'cgi_monitoring_software',
  description: "Monitoring software for CGI or equivalent programs",
  default: 'monitoringsoftware'
)

only_if do
  command('nginx').exist?
end

control "V-2271" do
  title "Monitoring software must include CGI or equivalent programs in its
  scope."
  desc "By their very nature, CGI type files permit the anonymous web user to
  interact with data and perhaps store data on the web server. In many cases,
  CGI scripts exercise system-level control over the server’s resources. These
  files make appealing targets for the malicious user. If these files can be
  modified or exploited, the web server can be compromised. These files must
  be monitored by a security tool that reports unauthorized changes to these
  files."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "WG440"
  tag "gid": "V-2271"
  tag "rid": "SV-32927r2_rule"
  tag "stig_id": "WG440 A22"
  tag "nist": ["AU-6", "AC-3", "Rev_4"]

  tag "check": "CGI or equivalent files must be monitored by a security tool
  that reports unauthorized changes. It is the purpose of such software to
  monitor key files for unauthorized changes to them. The reviewer should
  query the ISSO, the SA, and the web administrator and verify the information
  provided by asking to see the template file or configuration file of the
  software being used to accomplish this security task. Example file
  extensions for files considered to provide active content are, but not
  limited to, .cgi, .asp, .aspx, .class, .vb, .php, .pl, and .c.

  If the site does not have a process in place to monitor changes to CGI program
  files, this is a finding."

  tag "fix": "Use a monitoring tool to monitor changes to the CGI or
  equivalent directory. This can be done with something as simple as a script or
  batch file that would identify a change in the file."

  # STOP_DESCRIBE V-2271
  describe package(CGIMONITORINGSOFTWARE) do
    it{ should be_installed }
  end
  # STOP_DESCRIBE V-2271
end
