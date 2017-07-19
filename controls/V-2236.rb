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

only_if do
  command('nginx').exist?
end

control "V-2236" do

  title "Installation of a compiler on production web server is prohibited."

  desc "The presence of a compiler on a production server facilitates the
  malicious user’s task of creating custom versions of programs and installing
  Trojan Horses or viruses. For example, the attacker’s code can be uploaded
  and compiled on the server under attack."

  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "WG080"
  tag "gid": "V-2236"
  tag "rid": "SV-32956r3_rule"
  tag "stig_id": "WG080 A22"
  tag "nist": ["CM-6", "Rev_4"]

  tag "check": "Query the SA and the Web Manager to determine if a compiler is
  present on the server.If a compiler is present, this is a finding.

  NOTE:  If the web server is part of an application suite and a compiler is
  needed for installation, patching, and upgrading of the suite or if the
  compiler is embedded and can't be removed without breaking the suite, document
  the installation of the compiler with the ISSO/ISSM and verify that the
  compiler is restricted to administrative users only.  If documented and
  restricted to administrative users, this is not a finding. "

  tag "fix": "Remove any compiler found on the production web server, but if
  the compiler program is needed to patch or upgrade an application suite in a
  production environment or the compiler is embedded and will break the suite
  if removed, document the compiler installation with the ISSO/ISSM and ensure
  that the compiler is restricted to only administrative users."


end
