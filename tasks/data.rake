require 'faker'

namespace :rla do
  namespace :data do
    
    desc "Generate cisco sample data file"
    task :cisco do
      File.open('./spec/fixtures/cisco.log', 'w') do |f|  
         1000.times { f.puts random_cisco_syslog_line }
      end 
    end
    
  end
end


# generates a valid log entry for the cisco syslong
def random_cisco_syslog_line
  case rand(3)
  when 0
    "#{random_time} #{Faker::Internet::ip_v4_address} %PIX-3-106011: Deny inbound (No xlate) udp src outside:#{Faker::Internet::ip_v4_address}/6970 dst outside:#{Faker::Internet::ip_v4_address}/21076"
  when 1
    "#{random_time} #{Faker::Internet::ip_v4_address} %PIX-6-302013: Built inbound TCP connection 9899285 for outside:#{Faker::Internet::ip_v4_address}/52397 (#{Faker::Internet::ip_v4_address}/52397) to inside:#{Faker::Internet::ip_v4_address}/443 (#{Faker::Internet::ip_v4_address}/443)"
  when 2   
    "#{random_time} #{Faker::Internet::ip_v4_address} %ASA-6-302020: Built inbound ICMP connection for faddr #{Faker::Internet::ip_v4_address}/9258 gaddr #{Faker::Internet::ip_v4_address}/0 laddr #{Faker::Internet::ip_v4_address}/0"
  end
end

# Build a random time as a string.  Follows the time
# formatting convention of the cisco syslog
def random_time(years_back=2 )
   year = Time.now.year - rand(years_back) - 1
   month = rand(12) + 1
   day = rand(31) + 1
   hour = rand(24)
   min = rand(60)
   sec = rand(60)
   Time.local(year, month, day, hour, min, sec).strftime('%Y-%m-%dT%H:%M:%S%z')
end