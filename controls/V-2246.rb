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

NGINX_VER = attribute(
  'nginx_ver',
  description: 'Minimum Web vendor-supported version.',
  default: '1.13.0'
)

only_if do
  command('nginx').exist?
end


control "V-2246" do   
  title "Web server software must be a vendor-supported version."   
  desc "Many vulnerabilities are associated with older versions of
  web server   software. As hot fixes and patches are issued, these solutions
  are included   in the next version of the server software. Maintaining the web
  server at a   current version makes the efforts of a malicious user to exploit
  the web   service more difficult."
  impact 0.7   
  tag "severity": "high"   
  tag "gtitle": "WG190"   
  tag "gid": "V-2246"   
  tag "rid": "SV-36441r2_rule"   
  tag "stig_id": "WG190 A22"   
  tag "nist": ["CM-6", "Rev_4"]   

  tag "check": "To determine the version of the nginx software that is running
  on the system. Use the command:

  nginx -v

  If the version of nginx is not at the following version or higher, this is a
  finding.

  nginx version: nginx/1.13.0

  Note: In some situations, the nginx software that is being used is supported
  by another vendor, such as nginx.com.  The versions of the software in these
  cases may not match the above mentioned version numbers. If the site can
  provide vendor documentation showing the version of the web server is
  supported, this would not be a finding. "

  tag "fix": "Install the current version of the web server software and
  maintain appropriate service packs and patches."

# START_DESCRIBE V-2246
    version = package('nginx').version.to_s.split('-')[0]
    describe version do
        it{should cmp >= NGINX_VER }
    end
# STOP_DESCRIBE V-2246
end
