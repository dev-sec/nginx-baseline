# encoding: utf-8
#
# Copyright 2015, Patrick Muench
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# author: Christoph Hartmann
# author: Dominik Richter
# author: Patrick Muench

title 'NGINX server config'

only_if do
  command('nginx').exist?
end

# determine all required paths
nginx_path      = '/etc/nginx'
nginx_conf      = File.join(nginx_path, 'nginx.conf')
nginx_confd     = File.join(nginx_path, 'conf.d')
nginx_enabled   = File.join(nginx_path, 'sites-enabled')
nginx_hardening = File.join(nginx_confd, '90.hardening.conf')
conf_paths      = [nginx_conf, nginx_hardening]

options = {
  assignment_regex: /^\s*([^:]*?)\s*\ \s*(.*?)\s*;$/
}

options_add_header = {
  assignment_regex: /^\s*([^:]*?)\s*\ \s*(.*?)\s*;$/,
  multiple_values: true
}

control 'nginx-01' do
  impact 1.0
  title 'Running worker process as non-privileged user'
  desc 'The NGINX worker processes should run as non-privileged user. In case of compromise of the process, an attacker has full access to the system.'
  describe user(nginx_lib.valid_users) do
    it { should exist }
  end
  describe parse_config_file(nginx_conf, options) do
    its('user') { should eq nginx_lib.valid_users }
  end

  describe parse_config_file(nginx_conf, options) do
    its('group') { should_not eq 'root' }
  end
end

control 'nginx-02' do
  impact 1.0
  title 'Check NGINX config file owner, group and permissions.'
  desc 'The NGINX config file should owned by root, only be writable by owner and not write- and readable by others.'
  describe file(nginx_conf) do
    it { should be_owned_by 'root' }
    it { should be_grouped_into 'root' }
    it { should_not be_readable.by('others') }
    it { should_not be_writable.by('others') }
    it { should_not be_executable.by('others') }
  end
end

control 'nginx-03' do
  impact 1.0
  title 'Nginx default files'
  desc 'Remove the default nginx config files.'
  describe file(File.join(nginx_confd, 'default.conf')) do
    it { should_not be_file }
  end

  describe file(File.join(nginx_enabled, 'default')) do
    it { should_not be_file }
  end

  conf_paths.each do |conf_path|
    describe file(conf_path) do
      it { should be_file }
    end
  end
end

control 'nginx-04' do
  impact 1.0
  title 'Check for multiple instances'
  desc 'Different instances of the nginx webserver should run in separate environments'
  describe command('ps aux | egrep "nginx: master" | egrep -v "grep" | wc -l') do
    its(:stdout) { should match(/^1$/) }
  end
end

control 'nginx-05' do
  impact 1.0
  title 'Disable server_tokens directive'
  desc 'Disables emitting nginx version in error messages and in the “Server” response header field.'
  describe parse_config_file(nginx_conf, options) do
    its('server_tokens') { should eq 'off' }
  end
end

control 'nginx-06' do
  impact 1.0
  title 'Prevent buffer overflow attacks'
  desc 'Buffer overflow attacks are made possible by writing data to a buffer and exceeding that buffer boundary and overwriting memory fragments of a process. To prevent this in nginx we can set buffer size limitations for all clients.'
  describe parse_config_file(nginx_conf, options) do
    its('client_body_buffer_size') { should eq '1k' }
  end
  describe parse_config_file(nginx_conf, options) do
    its('client_max_body_size') { should eq '1k' }
  end
  describe parse_config_file(nginx_hardening, options) do
    its('client_header_buffer_size') { should eq '1k' }
  end
  describe parse_config_file(nginx_hardening, options) do
    its('large_client_header_buffers') { should eq '2 1k' }
  end
end

control 'nginx-07' do
  impact 1.0
  title 'Control timeouts to improve performance'
  desc 'Control timeouts to improve server performance and cut clients.'
  describe parse_config_file(nginx_conf, options) do
    its('keepalive_timeout') { should eq '5 5' }
  end
  describe parse_config_file(nginx_hardening, options) do
    its('client_body_timeout') { should eq '10' }
  end
  describe parse_config_file(nginx_hardening, options) do
    its('client_header_timeout') { should eq '10' }
  end
  describe parse_config_file(nginx_hardening, options) do
    its('send_timeout') { should eq '10' }
  end
end

control 'nginx-07' do
  impact 1.0
  title 'Control simultaneous connections'
  desc 'NginxHttpLimitZone module to limit the number of simultaneous connections for the assigned session or as a special case, from one IP address.'
  describe parse_config_file(nginx_hardening, options) do
    its('limit_conn_zone') { should eq '$binary_remote_addr zone=default:10m' }
  end
  describe parse_config_file(nginx_hardening, options) do
    its('limit_conn') { should eq 'default 5' }
  end
end

control 'nginx-08' do
  impact 1.0
  title 'Prevent clickjacking'
  desc 'Do not allow the browser to render the page inside an frame or iframe.'
  describe parse_config_file(nginx_hardening, options_add_header) do
    its('add_header') { should include 'X-Frame-Options SAMEORIGIN' }
  end
end

control 'nginx-09' do
  impact 1.0
  title 'Enable Cross-site scripting filter'
  desc 'This header is used to configure the built in reflective XSS protection. This tells the browser to block the response if it detects an attack rather than sanitising the script.'
  describe parse_config_file(nginx_hardening, options_add_header) do
    its('add_header') { should include 'X-XSS-Protection "1; mode=block"' }
  end
end

control 'nginx-10' do
  impact 1.0
  title 'Disable content-type sniffing'
  desc 'It prevents browser from trying to mime-sniff the content-type of a response away from the one being declared by the server. It reduces exposure to drive-by downloads and the risks of user uploaded content that, with clever naming, could be treated as a different content-type, like an executable.'
  describe parse_config_file(nginx_hardening, options_add_header) do
    its('add_header') { should include 'X-Content-Type-Options nosniff' }
  end
end
