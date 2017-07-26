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

control "V-2261" do
  title "A public web server must limit email to outbound only."

  desc" Incoming E-mail has been known to provide hackers with access to
  servers. Disabling the incoming mail service prevents this type of attacks.
  Additionally, Email represents the main use of the Internet. It is
  specialized application that requires the dedication of server resources. To
  combine this type of transaction processing function with the file serving
  role of the web server creates an inherent conflict. Supporting mail
  services on a web server opens the server to the risk of abuse as an email
  relay. falseWeb AdministratorECSC-1 "

  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "WG330"
  tag "gid": "V-2261"
  tag "rid": "SV-32937r1_rule"
  tag "stig_id": "WG330 A22"
  tag "nist": ["CM-6", "Rev_4"]

  tag "check": "\"To determine if email applications are excepting incoming
  connections (on standard ports)enter the following command:

  telnet localhost 25

  review the command results, If an e-mail program is installed and that program
  has been configured to accept inbound email, this is a finding.\" "

  tag "fix": "Configure the email application to not allow incoming connections."


# START_DESCRIBE V-2261

  describe port(25) do
    it { should_not be_listening }
  end

# STOP_DESCRIBE V-2261

end
