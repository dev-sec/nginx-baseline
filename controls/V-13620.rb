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

NGINX_CONF_FILE= attribute(
  'nginx_conf_file',
  description: 'Path for the nginx configuration file',
  default: "/etc/nginx/nginx.conf"
)

DOD_APPROVED_PKIS= attribute(
  'dod_approved_pkis',
  description: 'DoD-approved PKIs (e.g., DoD PKI, DoD ECA, and DoD-approved external partners).',
  default: ['DoD',
            'ECA']
)

only_if do
  command('nginx').exist?
end

control "V-13620" do

  title "A private web server’s list of CAs in a trust hierarchy must lead to
  an authorizedDoD PKI Root CA."

  desc "A PKI certificate is a digital identifier that establishes the identity
  of an individual or a platform. A server that has a certificate provides
  users with third-party confirmation of authenticity. Most web browsers
  perform server authentication automatically and the user is notified only if
  the authentication fails. The authentication process between the server and
  the client is performed using the SSL/TLS protocol. Digital certificates are
  authenticated, issued, and managed by a trusted Certificate Authority (CA).

  The use of a trusted certificate validation hierarchy is crucial to the
  ability to control access to a site’s server and to prevent unauthorized
  access. Only DoD-approved PKIs will be utilized. "

  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "WG355"
  tag "gid": "V-13620"
  tag "rid": "SV-32936r1_rule"
  tag "stig_id": "WG355 A22"
  tag "nist": ["IA-5", "SC-12", "Rev_4"]

  tag "check": "Enter the following command:

  find / -name ssl.conf  note the path of the file.

  grep ""ssl_client_certificate"" in conf files in context http,server

  Review the results to determine the path of the ssl_client_certificate.

  more /path/of/ca-bundle.crt

  Examine the contents of this file to determine if the trusted CAs are DoD
  approved. If the trusted CA that is used to authenticate users to the web site
  does not lead to an approved DoD CA, this is a finding.

  NOTE: There are non DoD roots that must be on the server in order for it to
  function. Some applications, such as anti-virus programs, require root CAs to
  function. DoD approved certificate can include the External Certificate
  Authorities (ECA), if approved by the DAA. The PKE InstallRoot 3.06 System
  Administrator Guide (SAG), dated 8 Jul 2008, contains a complete list of DoD,
  ECA, and IECA CAs."

  tag "fix": "Configure the web server’s trust store to trust only DoD-
  approved PKIs (e.g., DoD PKI, DoD ECA, and DoD-approved external partners)."

  begin
    nginx_conf(NGINX_CONF_FILE).http.entries.each do |http|
      describe http.params['ssl_client_certificate'] do
        it { should_not be_nil}
      end
      http.params['ssl_client_certificate'].each do |cert|
        describe x509_certificate(cert.join) do
          it { should_not be_nil}
          its('subject.C') { should cmp 'US'}
          its('subject.O') { should cmp 'U.S. Government'}
        end
        describe x509_certificate(cert.join).subject.CN[0..2] do
          it { should be_in DOD_APPROVED_PKIS}
        end
      end unless http.params['ssl_client_certificate'].nil?
    end

    nginx_conf(NGINX_CONF_FILE).servers.entries.each do |server|
      server.params['ssl_client_certificate'].each do |cert|
        describe x509_certificate(cert.join) do
          it { should_not be_nil}
          its('subject.C') { should cmp 'US'}
          its('subject.O') { should cmp 'U.S. Government'}
        end
        describe x509_certificate(cert.join).subject.CN[0..2] do
          it { should be_in DOD_APPROVED_PKIS}
        end
      end unless server.params['ssl_client_certificate'].nil?
    end

  rescue Exception => msg
    describe "Exception: #{msg}" do
      it { should be_nil}
    end
  end
end
