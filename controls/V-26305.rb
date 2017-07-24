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


WEBSERVERROOT = attribute(
  'webserverroot',
  description: 'Path to webserve root directory',
  default: "/usr/share/nginx/html"
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

control "V-26305" do
  title "The process ID (PID) file must be properly secured."

  desc "The pid directive sets the file path to the process ID file to which
  the server records the process id of the server, which is useful for sending
  a signal to the server process or for checking on the health of the process.
  If the PID file is placed in a writable directory, other accounts could
  create a denial of service attack and prevent the server from starting by
  creating a PID file with the same name."

  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "WA00530"
  tag "gid": "V-26305"
  tag "rid": "SV-33222r1_rule"
  tag "stig_id": "WA00530 A22"
  tag "nist": ["AC-3", "Rev_4"]

  tag "check": "To find the pid file:

  grep ""pid""+N52 The pid directive will indicate the location of the pid file
  (typical default: /usr/sbin/nginx.pid)

  Verify the permissions and ownership on the folder containing the PID file. If
  any user accounts other than root, auditor, or the account used to run the web
  server have permission to, or ownership of, this folder, this is a finding. If
  the PID file is located in the  web server Root this is a finding."

  tag "fix": "Modify the location, permissions, and/or ownership for the PID
  file folder. "

  # START_DESCRIBE V-26305
  authorized_owner_list = [ NGINX_OWNER, SYS_ADMIN ]
  authorized_group_list = [ NGINX_GROUP, SYS_ADMIN_GROUP ]

  describe file(nginx_conf(NGINX_CONF_FILE).pid.join) do
    it { should exist}
    its ('owner') { should be_in authorized_owner_list}
    its ('group') { should be_in authorized_group_list}
  end

  describe nginx_conf(NGINX_CONF_FILE) do
    its ('pid.join') { should_not match %r(#{WEBSERVERROOT})}
  end
  # STOP_DESCRIBE V-26305

end
