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

control "V-13732" do
  title "The ""disable_symlinks"" setting must be on."
  desc "The disable_symlinks directive determines how symbolic links should be
  treated when opening files.A symbolic link allows a file or a directory to
  be referenced using a symbolic name raising a potential hazard if symbolic
  linkage is made to a sensitive area. When web scripts are executed and
  symbolic links are allowed, the web user could be allowed to access
  locations on the web server that are outside the scope of the web document
  root or home directory."

  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "WA000-WWA052"
  tag "gid": "V-13732"
  tag "rid": "SV-40129r1_rule"
  tag "stig_id": "WA000-WWA052 A22"
  tag "nist": ["CM-6", "Rev_4"]

  tag "check": "To view the disable_symlinks directive value enter the
  following command:

  grep ""disable_symlinks"" on the nginx.conf file and any separate included
  configuration files

  If the value of ""disable_symlinks"" is not set to on, this is a finding:

  disable_symlinks   on;

  If any component of the pathname is a symbolic link, access to a file is
  denied.  "

  tag "fix": "Edit the configuration file and set the value of
  ""disable_symlinks"" to on:

  disable_symlinks   on;"

  begin
    nginx_conf(NGINX_CONF_FILE).http.entries.each do |http|
      describe http.params['disable_symlinks'] do
        it { should cmp [['on']] }
      end
    end

    nginx_conf(NGINX_CONF_FILE).servers.entries.each do |server|
      describe server.params['disable_symlinks'] do
        it { should cmp [['on']] }
      end unless server.params['disable_symlinks'].nil?
    end

    nginx_conf(NGINX_CONF_FILE).locations.entries.each do |location|
      describe location.params['disable_symlinks'] do
        it { should cmp [['on']] }
      end unless location.params['disable_symlinks'].nil?
    end

  rescue Exception => msg
    describe "Exception: #{msg}" do
      it { should be_nil}
    end
  end

end
