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

control "V-13726" do
  title "The KeepAliveTimeout directive must be defined."

  desc "The number of seconds Apache will wait for a subsequent request before
  closing the connection. Once a request has been received, the timeout value
  specified by the Timeout directive applies. Setting KeepAliveTimeout to a
  high value may cause performance problems in heavily loaded servers. The
  higher the timeout, the more server processes will be kept occupied waiting
  on connections with idle clients. These requirements are set to mitigate the
  effects of several types of denial of service attacks. "

  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "WA000-WWA024"
  tag "gid": "V-13726"
  tag "rid": "SV-32877r1_rule"
  tag "stig_id": "WA000-WWA024 A22"
  tag "nist": ["CM-6", "Rev_4"]

  tag "check": "To view the keepalive_timeout directive value enter the
  following command:

  grep ""keepalive_timeout"" on the nginx.conf file and any separate included
  configuration files

  If the value of ""keepalive_timeout"" is not set to 5 (seconds) or less, this
  is a finding:

  keepalive_timeout   5 5;

  The first parameter sets a timeout during which a keep-alive client connection
  will stay open on the server side. The zero value disables keep-alive client
  connections. The second parameter sets a value in the “Keep-Alive:
  timeout=time” response header field. The “Keep-Alive: timeout=time” header
  field is recognized by Mozilla and Konqueror. "

  tag "fix": "Edit the configuration file and set the value of
  ""keepalive_timeout"" to the value of 5 or less:

  keepalive_timeout   5 5;"

  # START_DESCRIBE V-13726
  nginx_conf(NGINX_CONF_FILE).params['http'].each do |http|
    describe http['keepalive_timeout'] do
      it { should cmp [['5', '5']] }
    end
  end

  if !nginx_conf(NGINX_CONF_FILE).http.nil?
    nginx_conf(NGINX_CONF_FILE).http.each do |http|
      if !http['server'].nil?
        http['server'].each do |server|
          if !server['keepalive_timeout'].nil?
            describe server['keepalive_timeout'] do
              it { should cmp [['5', '5']] }
            end
          end
          if !server['location'].nil?
            server['location'].each do |location|
              if !location['keepalive_timeout'].nil?
                describe location['keepalive_timeout'] do
                  it { should cmp [['5', '5']] }
                end
              end
            end
          end
        end
      end
    end
  end
  # STOP_DESCRIBE V-13726
end
