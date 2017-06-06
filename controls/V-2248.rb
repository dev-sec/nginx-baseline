title 'V-2248 - Web administration tools must be restricted to the web manager and the web manager’s designees.'
control 'V-2248' do
  impact 0.5
  title 'Web administration tools must be restricted to the web manager and the web manager’s designees.'
  desc 'All automated information systems are at risk of data loss due to disaster or compromise. Failure to provide adequate protection to the administration tools creates risk of potential theft or damage that may ultimately compromise the mission.  Adequate protection ensures that server administration operates with less risk of losses or operations outages.  The key web service administrative and configuration tools must be accessible only by the authorized web server administrators. All users granted this authority must be documented and approved by the ISSO. Access to the IIS Manager will be limited to authorized users and administrators. '
  tag 'stig', 'V-2248'
  tag severity: 'medium'
  tag checkid: 'C-29923r1_chk'
  tag fixid: 'F-26807r1_fix'
  tag version: 'WG220 A22'
  tag ruleid: 'SV-32948r2_rule'
  tag nist: 'AC-3'
  tag fixtext: 'Restrict access to the web administration tool to only the web manager and the web manager’s designees.'
  tag checktext: 'Determine which tool or control file is used to control the configuration of the web server. 

If the control of the web server is done via control files, verify who has update access to them. If tools are being used to configure the web server, determine who has access to execute the tools.

If accounts other than the SA, the web manager, or the web manager designees have access to the web administration tool or control files, this is a finding.
'

# START_DESCRIBE V-2248
# No Check possible
# STOP_DESCRIBE V-2248

end

