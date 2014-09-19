# -*- coding: utf-8 -*-
module Serverspec
  module Type
    class NginxConf < Base
      def initialize(paths)
        @paths = paths
      end
      def content
        @paths.map { |x| ::File.read x }.join("\n")
      end
    end
    def nginx_conf(paths)
      NginxConf.new(paths)
    end
  end
end
include Serverspec::Type
