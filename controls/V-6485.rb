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

only_if do
  command('nginx').exist?
end

control "V-6485" do

  title "Web server content and configuration files must be part of a routine
  backup program."

  desc"Backing up web server data and web server application software after
  upgrades or maintenance ensures that recovery can be accomplished up to the
  current version. It also provides a means to determine and recover from
  subsequent unauthorized changes to the software and data.

  A tested and verifiable backup strategy will be implemented for web server
  software as well as all web server data files. Backup and recovery procedures
  will be documented and the Web Manager or SA for the specific application will
  be responsible for the design, test, and implementation of the procedures.

  The site will have a contingency processing plan/disaster recovery plan that
  includes web servers. The contingency plan will be periodically tested in
  accordance with DoDI 8500.2 requirements.

  The site will identify an off-site storage facility in accordance with DoDI
  8500.2 requirements. Off-site backups will be updated on a regular basis and
  the frequency will be documented in the contingency plan. "

  impact 0.3
  tag "severity": "low"
  tag "gtitle": "WA140"
  tag "gid": "V-6485"
  tag "rid": "SV-32964r2_rule"
  tag "stig_id": "WA140 A22"
  tag "nist": ["CP-9", "Rev_4"]

  tag "check": "Interview the Information Systems Security Officer (ISSO), SA,
  Web Manager, Webmaster or developers as necessary to determine whether or
  not a tested and verifiable backup strategy has been implemented for web
  server software as well as all web server data files.

  Proposed Questions: Who maintains the backup and recovery procedures? Do you
  have a copy of the backup and recovery procedures? Where is the off-site
  backup location? Is the contingency plan documented? When was the last time
  the contingency plan was tested? Are the test dates and results documented?

  If there is not a backup and recovery process for the web server, this is a
  finding. "

  tag "fix": "Document the backup procedures."

  only_if {
    false
  }
end
