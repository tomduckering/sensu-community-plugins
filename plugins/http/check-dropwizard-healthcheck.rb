#!/usr/bin/env ruby
#
# Check Drop Wizard Healthcheck
# ===
#
# Takes either a URL or a combination of host/path/port/ssl, and checks for
# valid JSON output in the response and will check each healthcheck for it's
# status - returning the error message in the event of a problem.
#
# Based on Matt Revell's check-json
# Based on Check HTTP by Sonian Inc.
#
# Released under the same terms as Sensu (the MIT license); see LICENSE
# for details.

require 'rubygems' if RUBY_VERSION < '1.9.0'
require 'sensu-plugin/check/cli'
require 'json'
require 'net/http'
require 'net/https'

class CheckDropWizardHealthcheck < Sensu::Plugin::Check::CLI

  option :url, :short => '-u URL'
  option :host, :short => '-h HOST'
  option :path, :short => '-p PATH'
  option :port, :short => '-P PORT', :proc => proc { |a| a.to_i }
  option :header, :short => '-H HEADER', :long => '--header HEADER'
  option :ssl, :short => '-s', :boolean => true, :default => false
  option :insecure, :short => '-k', :boolean => true, :default => false
  option :user, :short => '-U', :long => '--username USER'
  option :password, :short => '-a', :long => '--password PASS'
  option :cert, :short => '-c FILE'
  option :cacert, :short => '-C FILE'
  option :timeout, :short => '-t SECS', :proc => proc { |a| a.to_i }, :default => 15
  option :ua, :short => '-x USER-AGENT', :long => '--user-agent USER-AGENT', :default => 'Sensu-HTTP-Check'

  def run
    if config[:url]
      uri = URI.parse(config[:url])
      config[:host] = uri.host
      config[:path] = uri.path
      config[:port] = uri.port
      config[:ssl] = uri.scheme == 'https'
    else
      unless config[:host] && config[:path]
        unknown 'No URL specified'
      end
      config[:port] ||= config[:ssl] ? 443 : 80
    end

    begin
      timeout(config[:timeout]) do
        get_resource
      end
    rescue Timeout::Error
      critical "Connection timed out"
    rescue => e
      critical "Connection error: #{e.message}"
    end
  end

  def json_valid?(str)
    JSON.parse(str)
    return true
  rescue JSON::ParserError
    return false
  end

  def get_resource
    http = Net::HTTP.new(config[:host], config[:port])

    if config[:ssl]
      http.use_ssl = true
      if config[:cert]
        cert_data = File.read(config[:cert])
        http.cert = OpenSSL::X509::Certificate.new(cert_data)
        http.key = OpenSSL::PKey::RSA.new(cert_data, nil)
      end
      if config[:cacert]
        http.ca_file = config[:cacert]
      end
      if config[:insecure]
        http.verify_mode = OpenSSL::SSL::VERIFY_NONE
      end
    end

    req = Net::HTTP::Get.new(config[:path],{'User-Agent' => config[:ua]})
    if (config[:user] != nil && config[:password] != nil)
      req.basic_auth config[:user], config[:password]
    end
    if config[:header]
      config[:header].split(',').each do |header|
        h, v = header.split(':', 2)
        req[h] = v.strip
      end
    end
    
    res = http.request(req)

    if ! res.is_a? Net::HTTPSuccess
      message = "Trouble reaching #{req.to_s} - #{res.message}"
      critical res.message
    else

      if json_valid?(res.body)
        json = JSON.parse(res.body)

        problems = {}
        json.each do |checkname, checkdata|
          if ! checkdata['healthy']
            problems[checkname] = checkdata['message']
          end
        end

        if problems.size == 0
          ok "All healthchecks are ok"
        else
          message = problems.to_json
          critical message
        end

      else
        critical "Response contains invalid JSON"
      end
    end
  end
end
