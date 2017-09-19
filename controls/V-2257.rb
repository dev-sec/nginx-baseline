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


SYS_ADMIN = attribute(
  'sys_admin',
  description: "The system adminstrator",
  default: 'root'
)

NGINX_OWNER = attribute(
  'nginx_owner',
  description: "The Nginx owner",
  default: 'nginx'
)

NGINX_CONF_FILE= attribute(
  'nginx_conf_file',
  description: 'define path for the nginx configuration file',
  default: "/etc/nginx/nginx.conf"
)

only_if do
  command('nginx').exist?
end

control "V-2257" do

  title "Administrative users and groups that have access rights to the web
  server must be documented."

  desc"There are typically several individuals and groups that are involved in
  running a production web server.These accounts must be restricted to only
  those necessary to maintain web services, review the server’s operation, and
  the operating system.By minimizing the amount of user and group accounts on
  a web server the total attack surface of the server is
  minimized.Additionally, if the required accounts aren’t documented no known
  standard is created.Without a known standard the ability to identify
  required accounts is diminished, increasing the opportunity for error when
  such a standard is needed (i.e. COOP, IR, etc.)."

  impact 0.3
  tag "severity": "low"
  tag "gtitle": "WA120"
  tag "gid": "V-2257"
  tag "rid": "SV-32951r1_rule"
  tag "stig_id": "WA120 A22"
  tag "nist": ["AC-2", "Rev_4"]

  tag "check": "Proposed Questions: How many user accounts are associated with
  the Web server operation and maintenance?

  Where are these accounts documented?

  Use the command line utility more /etc/passwd to identify the accounts on the
  web server.

  Query the SA or Web Manager regarding the use of each account and each group.

  If the documentation does not match the users and groups found on the server,
  this is a finding. "

  tag "fix": "Document the administrative users and groups which have access
  rights to the web server in the web site SOP or in an equivalent document."

  begin
    DOCUMENTED_ADMINS = [SYS_ADMIN, NGINX_OWNER]

    describe nginx_conf(NGINX_CONF_FILE).params['user'].flatten do
      it{ should be_in DOCUMENTED_ADMINS}
    end

  rescue Exception => msg
    describe "Exception: #{msg}" do
      it { should be_nil}
    end
  end

end
