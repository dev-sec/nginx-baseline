# encoding: utf-8
#
# Copyright 2016, Patrick Muench
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
  name 'nginx_conf_helper'

  def initialize(conf_path)
    @conf_path = conf_path
    @data = { 'http' => [],
              'server' => [],
              'location' => [] }
    # @data = []
  end

  def param_empty?
    @data['http'].empty? && @data['http'].empty? && @data['http'].empty?
  end

  def method_missing(name)
    params = inspec.nginx_conf(@conf_path).params
    name = name.to_s
    params['http'].each do |http|
      @data['http'].push(http[name]) unless http[name].nil?
      http['server'].each do |server|
        @data['server'].push(server[name]) unless server[name].nil?
        server['location'].each do |location|
          @data['location'].push(location[name]) unless location[name].nil?
        end unless server['location'].nil?
      end unless http['server'].nil?
    end unless params['http'].nil?
    @data
  end

end
