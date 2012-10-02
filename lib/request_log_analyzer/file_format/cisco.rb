module RequestLogAnalyzer::FileFormat

  # The Cisco file format parses Cisco PIX Firewall System Log messages.   
  # http://www.cisco.com/en/US/docs/security/pix/pix63/system/message/pixemint.html#wp1020170
  class Cisco < Base
    extend CommonRegularExpressions
      
    # 2012-09-16T09:05:02-04:00 10.113.15.199 %PIX-3-106011: Deny inbound (No xlate) udp src outside:211.79.36.208/6970 dst outside:199.253.247.63/21076
    line_definition :deny do |line|
      line.regexp = /(#{timestamp('%Y-%m-%dT%H:%M:%S%z')})\s.*Deny.*src.*\:(#{ip_address}).*dst.*\:(#{ip_address})/
      line.capture(:timestamp).as(:timestamp)
      line.capture(:source_ip)
      line.capture(:destination_ip)
      line.header = true
      line.footer = true
    end
    
    # 2012-09-16T09:05:00-04:00 10.153.160.71 %PIX-6-302013: Built inbound TCP connection 9899285 for outside:170.148.136.154/52397 (169.78.247.58/52397) to inside:170.148.140.14/443 (170.148.140.14/443)
    line_definition :built do |line|
      line.regexp = /(#{timestamp('%Y-%m-%dT%H:%M:%S%z')})\s.*Built.*\:(#{ip_address}).*\:(#{ip_address})/
      line.capture(:timestamp).as(:timestamp)
      line.capture(:source_ip)
      line.capture(:destination_ip)
      line.header = true
      line.footer = true
    end
    
    # 2012-09-16T09:05:01-04:00 10.244.97.196 %ASA-6-302020: Built inbound ICMP connection for faddr 159.53.110.155/9258 gaddr 159.53.114.11/0 laddr 159.53.114.11/0
    line_definition :gaddr do |line|
      line.regexp = /(#{timestamp('%Y-%m-%dT%H:%M:%S%z')})\s.*Built.* gaddr (#{ip_address})/
      line.capture(:timestamp).as(:timestamp)
      line.capture(:source_ip)
      line.header = true
      line.footer = true
    end
    
    # generate reports
    report do |analyze|
      analyze.timespan
    end

  end
end
