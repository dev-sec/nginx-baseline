# frozen_string_literal: true

# Copyright:: 2016, Patrick Muench
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

class Nginxlib < Inspec.resource(1)
  name 'nginx_lib'

  def valid_users
    # define nginx user for different distros

    centos_user = 'nginx'
    debian_user = 'www-data'
    web_user = debian_user

    # adjust the nginx user based on OS
    case inspec.os[:family]
    when 'ubuntu', 'debian'
      web_user
    when 'redhat', 'centos', 'fedora'
      web_user = centos_user
    end

    web_user
  end
end
