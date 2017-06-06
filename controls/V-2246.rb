title 'V-2246 - Web server software must be a vendor-supported version.'
control 'V-2246' do
  impact 1.0
  title 'Web server software must be a vendor-supported version.'
  desc 'Many vulnerabilities are associated with older versions of web server software. As hot fixes and patches are issued, these solutions are included in the next version of the server software. Maintaining the web server at a current version makes the efforts of a malicious user to exploit the web service more difficult.'
  tag 'stig', 'V-2246'
  tag severity: 'high'
  tag checkid: 'C-29915r5_chk'
  tag fixid: 'F-2295r5_fix'
  tag version: 'WG190 A22'
  tag ruleid: 'SV-36441r2_rule'
  tag nist: 'CM-6'
  tag fixtext: 'Install the current version of the web server software and maintain appropriate service packs and patches.'
  tag checktext: 'To determine the version of the nginx software that is running on the system. Use the command:

nginx –v


If the version of Nginx is not at the following version or higher, this is a finding.

Nginx version: nginx/1.13.0

Note: In some situations, the nginx software that is being used is supported by another vendor, such as nginx.com.
The versions of the software in these cases may not match the above mentioned version numbers. If the site can provide vendor documentation showing the version of the web server is supported, this would not be a finding.
'

# START_DESCRIBE V-2246
    version = package('nginx').version.split('-')[0]
    describe version do
        it{should cmp >= '1.12.0' }
    end
# STOP_DESCRIBE V-2246

end

