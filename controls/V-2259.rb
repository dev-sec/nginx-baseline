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
  description: 'define path for the nginx configuration file',
  default: "/etc/nginx/nginx.conf"
)

NGINX_OWNER = attribute(
  'nginx_owner',
  description: "The Nginx owner",
  default: 'nginx'
)

SYS_ADMIN = attribute(
  'sys_admin',
  description: "The system adminstrator",
  default: 'root'
)

NGINX_GROUP = attribute(
  'nginx_group',
  description: "The Nginx group",
  default: 'nginx'
)

SYS_ADMIN_GROUP = attribute(
  'sys_admin_group',
  description: "The system adminstrator group",
  default: 'root'
)


only_if do
  command('nginx').exist?
end

options = {
  assignment_regex: /^\s*([^:]*?)\s*\ \s*(.*?)\s*;$/
}

options_add_header = {
  assignment_regex: /^\s*([^:]*?)\s*\ \s*(.*?)\s*;$/,
  multiple_values: true
}

configuration_files   = ['/usr/sbin/nginx',
                        '/etc/nginx/',
                        '/etc/nginx/conf.d',
                        '/etc/nginx/modules',
                        '/usr/share/nginx/html',
                        '/var/log/nginx'
                        ]

control "V-2259" do

  title "Web server system files must conform to minimum file permission
  requirements."

  desc "This check verifies that the key web server system configuration files
  are owned by the SA or the web administrator controlled account. These same
  files that control the configuration of the web server, and thus its
  behavior, must also be accessible by the account that runs the web service.
  If these files are altered by a malicious user, the web server would no
  longer be under the control of its managers and owners; properties in the
  web server configuration could be altered to compromise the entire server
  platform."

  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "WG300"
  tag "gid": "V-2259"
  tag "rid": "SV-32938r1_rule"
  tag "stig_id": "WG300 A22"
  tag "nist": ["AC-3", "AC-6", "Rev_4"]

  tag "check": "Nginx directory and file permissions and ownership should be
  set per the following table.. The installation directories may vary from one
  installation to the next.If used, the WebAmins group should contain only
  accounts of persons authorized to manage the web server configuration,
  otherwise the root group should own all Nginx files and directories.

  If the files and directories are not set to the following permissions or more
  restrictive, this is a finding.

  grep for the ""root"" directive on the nginx.conf file and any separate
  included configuration files to find the Nginx root directory

  /usr/sbin/nginx       root WebAdmin  550/550
  /etc/nginx/           root WebAdmin 770/660
  /etc/nginx/conf.d     root WebAdmin 770/660
  /etc/nginx/modules    root WebAdmin 770/660
  /usr/share/nginx/html root WebAdmin  775/664
  /var/log/nginx        root WebAdmin  750/640

  NOTE:  The permissions are noted as directories / files"

  tag "fix": "Use the chmod command to set permissions on the web server
  system directories and files as follows.

  /usr/sbin/nginx       root WebAdmin  550/550
  /etc/nginx/           root WebAdmin 770/660
  /etc/nginx/conf.d     root WebAdmin 770/660
  /etc/nginx/modules    root WebAdmin 770/660
  /usr/share/nginx/html root WebAdmin  775/664
  /var/log/nginx        root WebAdmin  750/640
  "
  # STOP_DESCRIBE V-2259

  system_directories.each do |directory|
    describe.one do
      describe file(directory) do
        it { should be_owned_by SYS_ADMIN }
        its('group') { should cmp SYS_ADMIN_GROUP }
        its('mode') { should cmp <= 0660 }
      end
      describe file(directory) do
        it { should be_owned_by NGINX_OWNER }
        its('group') { should cmp NGINX_GROUP }
        its('mode') { should cmp <= 0660 }
      end
    end
  end
  # STOP_DESCRIBE V-2259
end