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


NGINX_DISALLOWED_FILE_LIST= attribute(
  'nginx_disallowed_file_list',
  description: 'File list of  documentation, sample code, example applications, and tutorials.',
  default: [ "/usr/share/man/man8/nginx.8.gz"
           ]
)

NGINX_EXCEPTION_FILES= attribute(
  'nginx_allowed_file_list',
  description: 'File list of allowed documentation, sample code, example applications, and tutorials.',
  default: [
           ]
)

NGINX_OWNER = attribute(
  'nginx_owner',
  description: 'Nginx owner',
  default: 'nginx'
  )

NGINX_GROUP = attribute(
  'nginx_group',
  description: 'Nginx owner',
  default: 'nginx'
  )


only_if do
  command('nginx').exist?
end

control "V-13621" do

  title "All web server documentation, sample code, example applications, and
  tutorials must be removed from a production web server."

  desc "Web server documentation, sample code, example applications, and
  tutorials may be an exploitable threat to a web server. A production web
  server may only contain components that are operationally necessary (e.g.,
  compiled code, scripts, web-content, etc.). Delete all directories that
  contain samples and any scripts used to execute the samples. If there is a
  requirement to maintain these directories at the site on non-production
  servers for training purposes, have permissions set to only allow access to
  authorized users (i.e., web administrators and systems administrators).
  Sample applications or scripts have not been evaluated and approved for use
  and may introduce vulnerabilities to the system."

  impact 0.7
  tag "severity": "high"
  tag "gtitle": "WG385"
  tag "gid": "V-13621"
  tag "rid": "SV-32933r1_rule"
  tag "stig_id": "WG385 A22"
  tag "nist": ["CM-6", "Rev_4"]

  tag "check": "Query the SA to determine if all directories that contain
  samples and any scripts used to execute the samples have been removed from
  the server. Each web server has its own list of sample files. This may
  change with the software versions, but the following are some examples of
  what to look for (This should not be the definitive list of sample files,
  but only an example of the common samples that are provided with the
  associated web server. This list will be updated as additional information
  is discovered.):

  ls -Ll /usr/share/man/man8/nginx.8.gz

  If there is a requirement to maintain these directories at the site for
  training or other such purposes, have permissions or set the permissions to
  only allow access to authorized users. If any sample files are found on the
  web server, this is a finding."

  # START_DESCRIBE V-13621
  NGINX_DISALLOWED_FILE_LIST.each do |file|
    describe file(file) do
      it { should_not exist }
    end
  end

  NGINX_EXCEPTION_FILES.each do |file|
    describe file(file) do
      it { should exist }
      it { should be_owned_by NGINX_OWNER }
      it { should be_grouped_into NGINX_GROUP }
      its('mode') { should cmp '640' }
    end
  end

  if NGINX_EXCEPTION_FILES.empty?
    describe do
      skip "Skipped: nginx disallowed file list empty"
    end
  end

  if NGINX_DISALLOWED_FILE_LIST.empty?
    describe do
      skip "Skipped: nginx disallowed file list empty."
    end
  end
  # STOP_DESCRIBE V-13621
end
