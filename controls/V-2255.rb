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
  package('nginx').installed?
end

control "V-2255" do

  title "The web server’s htpasswd files (if present) must reflect proper
  ownership and permissions"

  desc "In addition to OS restrictions, access rights to files and directories
  can be set on a web site using the web server software.That is, in addition
  to allowing or denying all access rights, a rule can be specified that
  allows or denies partial access rights.For example, users can be given read-
  only access rights to files, to view the information but not change the
  files.

  This check verifies that the htpasswd file is only accessible by system
  administrators or web managers, with the account running the web service
  having group permissions of read and execute.  htpasswd is a utility used to
  provide for password access to web sites."

  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "WG270"
  tag "gid": "V-2255"
  tag "rid": "SV-36478r2_rule"
  tag "stig_id": "WG270 A22"
  tag "nist": ["AC-3", "Rev_4"]
  tag "check": "To locate the htpasswd file enter the following command:

  Find / -name htpasswd Permissions should be r-x r - x - - - (550)

  If permissions on htpasswd are greater than 550, this is a finding.

  Owner should be the SA or Web Manager account, if another account has access
  to this file, this is a finding. "

  tag "fix": "The SA or Web Manager account
  should own the htpasswd file and permissions should be set to 550."

# START_DESCRIBE V-2255
  htpasswd = command('find / -name .htpasswd').stdout.chomp
  htpasswd.split.each do |htpwd|
    describe file(htpwd) do
      its('mode') { should cmp <= 0550 }
    end
    describe file(htpwd) do
      its('owner') { should match %r(#{SYS_ADMIN}|#{NGINX_OWNER}) }
      its('group') { should match %r(#{SYS_ADMIN_GROUP}|#{NGINX_GROUP}) }
    end
  end

  if htpasswd.empty?
    describe do
      skip "Skipped: .htpasswd file not found"
    end
  end


# STOP_DESCRIBE V-2255

end
