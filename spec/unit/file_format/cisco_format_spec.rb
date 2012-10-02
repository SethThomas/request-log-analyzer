require 'spec_helper'

describe RequestLogAnalyzer::FileFormat::Cisco do    
  
    subject { RequestLogAnalyzer::FileFormat.load(:cisco) }
    it { should be_well_formed }    
    it { should have_line_definition(:deny).capturing(:timestamp,:source_ip,:destination_ip) }
    it { should have_line_definition(:built).capturing(:timestamp,:source_ip,:destination_ip) }
    it { should have_line_definition(:gaddr).capturing(:timestamp,:source_ip) }
    
    describe '#parse_line' do
      
      let(:deny_sample) { '2012-09-16T09:05:02-04:00 10.113.15.199 %PIX-3-106011: Deny inbound (No xlate) udp src outside:211.79.36.208/6970 dst outside:199.253.247.63/21076' }
      let(:built_sample) { '2012-09-16T09:05:00-04:00 10.153.160.71 %PIX-6-302013: Built inbound TCP connection 9899285 for outside:170.148.136.154/52397 (169.78.247.58/52397) to inside:170.148.140.14/443 (170.148.140.14/443)' }
      let(:gaddr_sample) { '2012-09-16T09:05:01-04:00 10.244.97.196 %ASA-6-302020: Built inbound ICMP connection for faddr 159.53.110.155/9258 gaddr 159.53.114.11/0 laddr 159.53.114.11/0' }
      
      
      it { should parse_line(deny_sample, 'a sample line')
        .and_capture(:timestamp => '2012-09-16T09:05:02-04:00',
                     :source_ip => '211.79.36.208',
                     :destination_ip => '199.253.247.63')
      }
      
      it { should parse_line(built_sample, 'a sample line')
        .and_capture(:timestamp => '2012-09-16T09:05:00-04:00',
                     :source_ip => '170.148.136.154',
                     :destination_ip => '170.148.140.14')
      }
      
      it { should parse_line(gaddr_sample, 'a sample line')
             .and_capture(:timestamp => '2012-09-16T09:05:01-04:00',
                          :source_ip => '159.53.114.11')
                          
      }

      it { should_not parse_line('nonsense', 'a nonsense line')}
      
      
      it { should have(1).report_trackers }
    end
    
    describe '#parse_io' do
      let(:log_parser) { RequestLogAnalyzer::Source::LogParser.new(subject) }
      
      it "should parse a log snippet successfully without warnings" do
        log_parser.should_receive(:handle_request).exactly(3).times
        log_parser.should_not_receive(:warn)
        log_parser.parse_file(log_fixture(:cisco))
      end
    end
    
end
