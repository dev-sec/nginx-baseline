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

OCSP_SERVER= attribute(
  'ocsp_server',
  description: 'domain and port to the OCSP Server ',
  default: 'login.live.com:443'
)

CRL_UDPATE_FREQUENCY= attribute(
  'crl_udpate_frequency',
  description: 'Frequency at which CRL is updated in days',
  default: 7
)

control "V-13672" do

  title "The private web server must use an approved DoD certificate
  validation process."

  desc  "Without the use of a certificate validation process, the site is
  vulnerable to accepting certificates that have expired or have been revoked.
  This would allow unauthorized individuals access to the web server.  This also
  defeats the purpose of the multi-factor authentication provided by the PKI
  process. "

  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "WG145"
  tag "gid": "V-13672"
  tag "rid": "SV-32954r2_rule"
  tag "stig_id": "WG145 A22"
  tag "nist": ["IA-5", "SC-12", "Rev_4"]

  tag "check": "The reviewer should query the ISSO, the SA, the web
  administrator, or developers as necessary to determine if the web server is
  configured to utilize an approved DoD certificate validation process.

  The web administrator should be questioned to determine if a validation
  process is being utilized on the web server.

  To validate this, the reviewer can ask the web administrator to describe the
  validation process being used. They should be able to identify either the use
  of certificate revocation lists (CRLs) or Online Certificate Status Protocol
  (OCSP).

  If the production web server is accessible, the SA or the web administrator
  should be able to demonstrate the validation of good certificates and the
  rejection of bad certificates.

  If CRLs are being used, the SA should be able to identify how often the CRL is
  updated and the location from which the CRL is downloaded.

  If the web administrator cannot identify the type of validation process being
  used, this is a finding."

  tag "fix": "Configure DoD Private Web Servers to conduct certificate
  revocation checking utilizing certificate revocation lists (CRLs) or Online
  Certificate Status Protocol (OCSP)."

  begin
    require 'time'

    #@todo complete ocsp verification test
    # oscp_status = command("openssl s_client -connect #{OCSP_SERVER} -tls1  -tlsextdebug  -status 2>&1 < /dev/null").stdout
    #
    # describe oscp_status do
    #   it { should match %r(OCSP Response Status: successful)}
    # end

    def days_since_crl_update(cert)
      ((Time.new - Time.at(file(cert).mtime.to_f)) / 86400)
    end

    nginx_conf(NGINX_CONF_FILE).http.entries.each do |http|
      describe http.params['ssl_crl'] do
        it { should_not be_nil}
      end
      http.params['ssl_crl'].each do |cert|
        describe file(cert.join) do
          it { should be_file }
        end
        describe days_since_crl_update(cert.join) do
          it { should cmp < CRL_UDPATE_FREQUENCY }
        end
      end unless http.params['ssl_crl'].nil?
    end

    nginx_conf(NGINX_CONF_FILE).servers.entries.each do |server|
      server.params['ssl_crl'].each do |cert|
        describe file(cert.join) do
          it { should be_file }
        end
        describe days_since_crl_update(cert.join) do
          it { should cmp < CRL_UDPATE_FREQUENCY }
        end
      end unless server.params['ssl_crl'].nil?
    end

  rescue Exception => msg
    describe "Exception: #{msg}" do
      it { should be_nil}
    end
  end
end
