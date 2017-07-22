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

NGINX_OWNER = attribute(
  'nginx_owner',
  description: "The Nginx owner",
  default: 'nginx'
)

only_if do
  command('nginx').exist?
end

control "V-2232" do

  title "The web server password(s) must be entrusted to the SA or Web
  Manager."

  desc "Normally, a service account is established for the web server. This is
  because a privileged account is not desirable and the server is designed to
  run for long uninterrupted periods of time. The SA or Web Manager will need
  password access to the web server to restart the service in the event of an
  emergency as the web server is not to restart automatically after an
  unscheduled interruption.If the password is not entrusted to an SA or web
  manager the ability to ensure the availability of the web server is
  compromised."

  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "WG050"
  tag "gid": "V-2232"
  tag "rid": "SV-32788r1_rule"
  tag "stig_id": "WG050 A22"
  tag "nist": ["AC-2", "Rev_4"]

  tag "check": "The reviewer should make a note of the name of the account
  being used for the web service. This information may be needed later in the
  SRR. There may also be other server services running related to the web server
  in support of a particular web application, these passwords must be entrusted
  to the SA or Web Manager as well. Query the SA or Web Manager to determine if
  they have the web service password(s).

  If the web services password(s) are not entrusted to the SA or Web Manager,
  this is a finding.

  NOTE: For installations that run as a service, or without a password, the SA
  or Web Manager having an Admin account on the system would meet the intent of
  this check. "

  tag "fix": "Ensure the SA or Web Manager are entrusted with the web
  service(s) password."

  describe passwd.users(NGINX_OWNER).passwords do
    it { should_not cmp ['']}
  end

end
