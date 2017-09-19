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

control "V-26326" do

  title "The web server must be configured to listen on a specific IP address
  and port."

  desc "The nginx listen directive specifies the IP addresses and port numbers
  the nginx web server will listen for requests. Rather than be unrestricted
  to listen on all IP addresses available to the system, the specific IP
  address or addresses intended must be explicitly specified. Specifically a
  Listen directive with no IP address specified, or with an IP address of
  zero’s should not be used. Having multiple interfaces on web servers is
  fairly common, and without explicit Listen directives, the web server is
  likely to be listening on an inappropriate IP address / interface that were
  not intended for the web server. Single homed system with a single IP
  addressed are also required to have an explicit IP address in the Listen
  directive, in case additional interfaces are added to the system at a later
  date."

  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "WA00555"
  tag "gid": "V-26326"
  tag "rid": "SV-33228r1_rule"
  tag "stig_id": "WA00555 A22"
  tag "nist": ["CM-7", "Rev_4"]

  tag "check": "Enter the following command:

  grep ""Listen""on the nginx.conf file and any separate included
  configuration files.

  Review the results for the followingdirective: listen

  For any enabled Listen directives ensure they specify both an IP address and
  port number.

  If the Listen directive is found with only an IP address, or only a port
  number specified, this is finding. If the IP address is all zeros (i.e.
  0.0.0.0:80 or [::ffff:0.0.0.0]:80, this is a finding. If the Listen
  directive does not exist, this is a finding."

  tag "fix": "Edit the nginx.conf file and set the ""listen"" directive to
  listen on a specific IP address and port. "

  begin
    nginx_conf(NGINX_CONF_FILE).servers.entries.each do |server|
      server.params['listen'].each do |listen|
        describe listen.join do
          it { should match %r([0-9]+(?:\.[0-9]+){3}|[a-zA-Z]:[0-9]+) }
        end
        describe listen.join.split(':').first do
          it { should_not cmp '0.0.0.0' }
          it { should_not cmp '[::ffff:0.0.0.0]' }
        end
      end unless server.params['listen'].nil?
    end
  rescue Exception => msg
    describe "Exception: #{msg}" do
      it { should be_nil}
    end
  end

end
