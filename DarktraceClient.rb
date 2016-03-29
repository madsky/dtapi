require 'net/http'
require 'openssl'

module Darktrace
    class Client
    
        def initialize
            @endpoint    = 'https://localhost'
            @public_key  = [public_key]
            @private_key = [private_key]
            @time        = Time.now.getutc.strftime('%Y%m%dT%H%M%S')
            @resources   = [
                'time'
            ]
        end

        def method_missing(method_id, *arguments)
            if @resources.include? method_id.to_s
                @uri = URI("#{@endpoint}/#{method_id.to_s}")
                self
            end
        end

        def get
            Net::HTTP::start(@uri.host, @uri.port,
              :use_ssl => @uri.scheme == 'https',
              :verify_mode => OpenSSL::SSL::VERIFY_NONE) do |http|

              request = Net::HTTP::Get.new @uri.request_uri
              request.add_field('DTAPI-Token', @public_key)
              request.add_field('DTAPI-Date', @time)
              request.add_field('DTAPI-Signature', signature())

              http.request request # Net::HTTPResponse object
            end
        end

        private
        def signature
            signature_sting = "#{@uri.request_uri}\n#{@public_key}\n#{@time}"
            OpenSSL::HMAC.hexdigest('sha1', @private_key, signature_sting)
        end
    end
end
