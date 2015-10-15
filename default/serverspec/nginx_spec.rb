# encoding: utf-8
#
# Copyright 2014, Deutsche Telekom AG
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

require 'spec_helper'

RSpec::Matchers.define :match_key_value do |key, value|
  match do |actual|
    actual =~ /^\s*?#{key}\s*?=\s*?#{value}/
  end
end

# determine all required paths
nginx_path      = '/etc/nginx'
nginx_conf      = File.join(nginx_path, 'nginx.conf')
nginx_confd     = File.join(nginx_path, 'conf.d')
nginx_enabled   = File.join(nginx_path, 'sites-enabled')
nginx_hardening = File.join(nginx_confd, '90.hardening.conf')
conf_paths      = [nginx_conf, nginx_hardening]

# check for files
describe 'nginx core configuration' do

  describe file(nginx_conf) do
    it { should be_owned_by 'root' }
    it { should be_grouped_into 'root' }
    it { should_not be_readable.by('others') }
    it { should_not be_writable.by('others') }
    it { should_not be_executable.by('others') }
  end

  # ... find stuff in conf.d and sites-available and sites-enabled + both folders
  # suid / sgid bits

end

describe 'nginx default files' do
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

describe 'Check for multiple instances' do
  describe command('ps aux | egrep "nginx: master" | egrep -v "grep" | wc -l') do
    its(:stdout) { should match(/^1$/) }
  end
end

# check configuration parameters
describe 'check nginx configuration' do

  describe file_with_includes(nginx_conf, /^\s*include.*;\s*$/) do
    its(:content) { should_not match(/^\s*user root;$/) }
    its(:content) { should_not match(/^\s*group root;$/) }
    its(:content) { should match(/^\s*server_tokens off;$/) }
    its(:content) { should match(/^\s*client_body_buffer_size\s*1k;$/) }
    its(:content) { should match(/^\s*client_max_body_size\s*1k;$/) }
    its(:content) { should match(/^\s*keepalive_timeout\s+5 5;$/) }
    its(:content) { should match(/^\s*client_header_buffer_size 1k;$/) }
    its(:content) { should match(/^\s*large_client_header_buffers 2 1k;$/) }
    its(:content) { should match(/^\s*client_body_timeout 10;$/) }
    its(:content) { should match(/^\s*client_header_timeout 10;$/) }
    its(:content) { should match(/^\s*send_timeout 10;$/) }
    its(:content) { should match(/^\s*limit_conn_zone \$binary_remote_addr zone=default:10m;$/) }
    its(:content) { should match(/^\s*limit_conn default 5;$/) }
    its(:content) { should match(/^\s*add_header X-Frame-Options SAMEORIGIN;$/) }
    its(:content) { should match(/^\s*add_header X-Content-Type-Options nosniff;$/) }
    its(:content) { should match(/^\s*add_header X-XSS-Protection "1; mode=block";$/) }
  end
end
