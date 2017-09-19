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

only_if do
  command('nginx').exist?
end

control "V-60707" do
  title "The web server must remove all export ciphers from the cipher suite."

  desc "During the initial setup of a Transport Layer Security (TLS) connection
  to the web server, the client sends a list of supported cipher suites in
  order of preference.The web server will reply with the cipher suite it will
  use for communication from the client list.If an attacker can intercept the
  submission of cipher suites to the web server and place, as the preferred
  cipher suite, a weak export suite, the encryption used for the session
  becomes easy for the attacker to break, often within minutes to hours."

  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "WG345"
  tag "gid": "V-60707"
  tag "rid": "SV-75159r1_rule"
  tag "stig_id": "WG345 A22"
  tag "nist": ["SC-8", "Rev_4"]

  tag "check": "Review the nginx.conf file and any separate included
  configuration files.

  Ensure the following entry exists:

  server {      # enables server-side protection from BEAST attacks
  ssl_prefer_server_ciphers on;

       # Disabled insecure ciphers suite. For example, MD5, DES, RC4, PSK
  ssl_ciphers ""ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-
  AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-
  AES128-SHA256:ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256
  :DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA:ECDHE-RSA-DES-
  CBC3-SHA:EDH-RSA-DES-CBC3-SHA:AES256-GCM-SHA384:AES128-GCM-
  SHA256:AES256-SHA256:AES128-SHA256:AES256-SHA:AES128-SHA:DES-
  CBC3-SHA:HIGH:!aNULL:!eNULL:!EXPORT:!DES:!MD5:!PSK:!RC4:@STRENGTH"";

   # -!MEDIUM：exclude encryption cipher suites using 128 bit encryption. LOW：
   # -!exclude encryption cipher suites using 64 or 56 bit encryption algorithms
   # -!EXPORT： exclude export encryption algorithms including 40 and 56 bits
   # -!algorithms. aNULL：  exclude the cipher suites offering no authentication.
   # -!This is currently the anonymous DH algorithms and anonymous ECDH
   # -!algorithms.
          # These cipher suites are vulnerable to a ""man in the middle"" attack
          # and so their use is normally discouraged.
   # -!eNULL：exclude the ""NULL"" ciphers that is those offering no encryption.
          # Because these offer no encryption at all and are a security risk
          # they are disabled unless explicitly included.
   # @STRENGTH：sort the current cipher list in order of encryption algorithm key
   # @length.



  If the entry is not found, this is a finding."

  tag "fix": "Review the nginx.conf file and any separate included
  configuration files.

  Edit to ensure the following entry exists:

  server {
       # enables server-side protection from BEAST attacks
       ssl_prefer_server_ciphers on;

     # Disabled insecure ciphers suite. For example, MD5, DES, RC4, PSK
  ssl_ciphers ""ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-
  AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-
  AES128-SHA256:ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256
  :DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA:ECDHE-RSA-DES-
  CBC3-SHA:EDH-RSA-DES-CBC3-SHA:AES256-GCM-SHA384:AES128-GCM-
  SHA256:AES256-SHA256:AES128-SHA256:AES256-SHA:AES128-SHA:DES-
  CBC3-SHA:HIGH:!aNULL:!eNULL:!EXPORT:!DES:!MD5:!PSK:!RC4:@STRENGTH"";

   # -!MEDIUM：exclude encryption cipher suites using 128 bit encryption.
   # -!LOW：   exclude encryption cipher suites using 64 or 56 bit encryption algorithms
   # -!EXPORT： exclude export encryption algorithms including 40 and 56 bits algorithms.
   # -!aNULL：  exclude the cipher suites offering no authentication. This is currently the anonymous DH algorithms and anonymous ECDH algorithms.
          # These cipher suites are vulnerable to a ""man in the middle"" attack and so their use is normally discouraged.
   # -!eNULL：exclude the ""NULL"" ciphers that is those offering no encryption.
          # Because these offer no encryption at all and are a security risk they are disabled unless explicitly included.
   # @STRENGTH：sort the current cipher list in order of encryption algorithm key length.
  }
  "

  begin
    disabled_ssl_ciphers = ['aNULL', 'eNULL', 'EXPORT', 'DES', 'MD5', 'PSK', 'RC4']
    nginx_conf_handle = nginx_conf(NGINX_CONF_FILE)

    nginx_conf_handle.http.entries.each do |http|
      describe http.params['ssl_prefer_server_ciphers'] do
        it { should cmp [['on']]}
      end
      describe http.params['ssl_ciphers'] do
        it { should_not be_nil }
      end

      unless http.params['ssl_ciphers'].nil?
        disabled_ssl_ciphers.each do |cipher|
          describe http.params['ssl_ciphers'].join do
            it { should match "!#{cipher}"}
          end
        end
        describe http.params['ssl_ciphers'].join do
          it { should match '@STRENGTH'}
        end
      end
    end

    nginx_conf_handle.servers.entries.each do |server|
      describe server.params['ssl_prefer_server_ciphers'] do
        it { should cmp [['on']]}
      end unless server.params['ssl_prefer_server_ciphers'].nil?

      unless server.params['ssl_ciphers'].nil?
        disabled_ssl_ciphers.each do |cipher|
          describe server.params['ssl_ciphers'].join do
            it { should match "!#{cipher}"}
          end
        end
        describe server.params['ssl_ciphers'].join do
          it { should match '@STRENGTH'}
        end
      end
    end

  rescue Exception => msg
    describe "Exception: #{msg}" do
      it { should be_nil}
    end
  end

end
