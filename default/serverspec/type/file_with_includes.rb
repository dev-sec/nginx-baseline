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

include Serverspec::Type

module Serverspec
  module Type
    class FileWithIncludes < Base
      def initialize(file_name, include_matcher)
        @name = file_name
        @runner = Specinfra::Runner
        @file_name = file_name
        @include_matcher = include_matcher
        @content_files = {}
      end

      def to_s
        type = self.class.name.split(':')[-1]
        type.gsub!(/([a-z\d])([A-Z])/, '\1 \2')
        type.capitalize!
        %(#{type} "#{@file_name}" with matcher "#{@include_matcher}")
      end

      def content
        if @content.nil?
          file = get_file_content(@file_name)

          file.scan(@include_matcher).each do |include_match|
            Dir.glob(include_match[/\/[^;]*/]).each do |file_name|
              included_file = get_file_content(file_name)
              file << included_file
            end

          end
          @content = file
        end
        @content
      end

      def get_file_content(file)
        if @content_files[file].nil?
          @content_files[file] = @runner.get_file_content(file).stdout
        end
        @content_files[file]
      end
    end

    def file_with_includes(file_name, include_matcher)
      FileWithIncludes.new(file_name, include_matcher)
    end
  end
end
