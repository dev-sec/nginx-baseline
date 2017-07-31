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


DMZ_SUBNET= attribute(
  'dmz_subnet',
  description: 'Subnet of the DMZ',
  default: '62.0.0.0/24'
)

NGINX_CONF_FILE= attribute(
  'nginx_conf_file',
  description: 'Path for the nginx configuration file',
  default: "/etc/nginx/nginx.conf"
)

only_if do
  command('nginx').exist?
end

control "V-2243" do

  title "A private web server must be located on a separate controlled access
  subnet."

  desc "Private web servers, which host sites that serve controlled access
  data, must be protected from outside threats in addition to insider threats.
  Insider threat may be accidental or intentional but, in either case, can
  cause a disruption in service of the web server. To protect the private web
  server from these threats, it must be located on a separate controlled
  access subnet and must not be a part of the public DMZ that houses the
  public web servers. It also cannot be located inside the enclave as part of
  the local general population LAN."

  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "WA070"
  tag "gid": "V-2243"
  tag "rid": "SV-32935r1_rule"
  tag "stig_id": "WA070 A22"
  tag "nist": ["SC-7", "Rev_4"]

  tag "check": "Verify the site’s network diagram and visually check the web
  server, to ensure that the private web server is located on a separate
  controlled access subnet and is not a part of the public DMZ that houses the
  public web servers. In addition, the private web server needs to be isolated
  via a controlled access mechanism from the local general population LAN."

  tag "fix": "Isolate the private web server from the public DMZ and separate
  it from the internal general population LAN."

  require "ipaddr"

  # collect and test each listen IPs from nginx_conf

  if !nginx_conf(NGINX_CONF_FILE).http.nil?
    nginx_conf(NGINX_CONF_FILE).http.each do |http|
      if !http['server'].nil?
        http['server'].each do |server|
          if !server['listen'].nil?
            server['listen'].each do |listen|
              describe listen.join do
                it { should match %r([0-9]+(?:\.[0-9]+){3}|[a-zA-Z]:[0-9]+) }
              end
              server_ip = listen.join.split(':').first
              server_ip = server_ip.eql?('localhost') ? '127.0.0.1' : server_ip
              if !(IPAddr.new(server_ip) rescue nil).nil?
                describe IPAddr.new(DMZ_SUBNET) === IPAddr.new(server_ip) do
                  it { should be false}
                end
              end
            end
          else
            describe do
              skip "Skipped: Listen tag not found."
            end
          end
        end
      end
    end
  end
end
