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

AUTHORIZED_PROCESS_LIST = attribute(
  'authorized_process_list',
  description: "List of authorized running processes",
  default: [ 'nginx',
             'systemd',
             'systemd-journal',
             'systemd-udevd',
             'systemd-logind',
             'dbus-daemon',
             'agetty',
             'bash',
             'ps'
           ]
)

only_if do
  command('nginx').exist?
end

control "V-2251" do

  title "All utility programs, not necessary for operations, must be removed
  or disabled. "

  desc  "Just as running unneeded services and protocols is a danger to the
  web server at the lower levels of the OSI model, running unneeded utilities
  and programs is also a danger at the application layer of the OSI model.
  Office suites, development tools, and graphical editors are examples of such
  programs that are troublesome. Individual productivity tools have no
  legitimate place or use on an enterprise, production web server and they are
  also prone to their own security risks."

  impact 0.3
  tag "severity": "low"
  tag "gtitle": "WG130"
  tag "gid": "V-2251"
  tag "rid": "SV-32955r2_rule"
  tag "stig_id": "WG130 A22"
  tag "nist": ["CM-6", "Rev_4"]

  tag "check": "If the site requires the use of a particular piece of
  software, the ISSO will need to maintain documentation identifying this
  software as necessary for operations. The software must be operated at the
  vendor’s current patch level and must be a supported vendor release. If
  programs or utilities that meet the above criteria are installed on the Web
  Server, and appropriate documentation and signatures are in evidence, this is
  not a finding.

  Determine whether the web server is configured with unnecessary software.

  Determine whether processes other than those that support the web server are
  loaded and/or run on the web server.

  Examples of software that should not be on the web server are all web
  development tools, office suites (unless the web server is a private web
  development server), compilers, and other utilities that are not part of the
  web server suite or the basic operating system.

  Check the directory structure of the server and ensure that additional,
  unintended, or unneeded applications are not loaded on the system.

  If, after review of the application on the system, there is no justification
  for the identified software, this is a finding.  "

  tag "fix": "Remove any unnecessary applications."


  begin
    ps_list = command('ps -A').stdout.scan(/[0-9][0-9]:[0-9][0-9]:[0-9][0-9]\s(.+)/).flatten.uniq

    describe ps_list do
      it { should be_in AUTHORIZED_PROCESS_LIST}
    end

    if ps_list.empty?
      describe do
        skip "Skipped: no processes parsed."
      end
    end

  rescue Exception => msg
    describe "Exception: #{msg}" do
      it { should be_nil}
    end
  end
end
