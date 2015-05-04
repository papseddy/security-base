# network.pp

class security::network {
	case $operatingsystem {
		'RedHat', 'CentOS': {	
			package { "dhcp": 
        		        ensure => absent;
        		}
	
  			augeas { "Disable IPv6 - /etc/sysconfig/network" : 
        	        	context => "/files/etc/sysconfig/network",
        	        	changes => [
        	        	        "set NETWORKING_IPV6 no",
        	        	        "set IPV6INIT no"
        	        	]
        		}
	
	        	augeas { "Disable IPv6 - /etc/modprobe.d/ipv6.conf": 
	                	context => "/files/etc/modprobe.d/ipv6.conf",
	                	changes => [
	                	                "set options[. = 'ipv6'] 'ipv6'",
	                	                "set options[. = 'ipv6']/disable '1'"
	                	]
	        	}
	  
	  		package { "tcp_wrappers": 
	        	        ensure => present;
       		 	}
	
		}

		'Ubuntu' : {

			package { "isc-dhcp-client":
				 ensure => absent;
			}
			
			augeas { "Disable IPv6" :
				context => "/files/etc/sysctl.conf",
				changes	=> [
					   "set net.ipv6.conf.all.disable_ipv6 1",
					   "set net.ipv6.conf.default.disable_ipv6 1",
					   "set net.ipv6.conf.lo.disable_ipv6 1"
				]
			}
			
			package { "tcpd" :
				ensure	=> installed,
			}

		}
	}
	
	file { "/etc/hosts.allow": 
       	       	links => "follow",
       	       	mode  => '0644';
       	}

        file { "/etc/hosts.deny": 
	      	links => "follow",
               	mode  => '0644';
        }
        	
       	augeas { "Modify Network Parameters (Host and Router)":
               	context => "/files/etc/sysctl.conf",
               	lens    => "sysctl.lns",
               	incl    => "/etc/sysctl.conf",
               	changes => [
                       	"set net.ipv4.conf.all.accept_source_route 0",
                       	"set net.ipv4.conf.default.accept_source_route 0",
                       	"set net.ipv4.conf.all.accept_redirects 0",
                       	"set net.ipv4.conf.default.accept_redirects 0",
                       	"set net.ipv4.conf.all.secure_redirects 0",
                       	"set net.ipv4.conf.default.secure_redirects 0",
                       	"set net.ipv4.conf.all.log_martians 1",
                      	"set net.ipv4.conf.default.log_martians 1",
       	               	"set net.ipv4.icmp_echo_ignore_broadcasts 1",
       		       	"set net.ipv4.icmp_ignore_bogus_error_responses 1",
              		"set net.ipv4.conf.all.rp_filter 1",
                        "set net.ipv4.conf.default.rp_filter 1",
                        "set net.ipv4.tcp_syncookies 1",
                       	"set net.ipv6.conf.all.accept_ra 0",
                        "set net.ipv6.conf.default.accept_ra 0"
                ];
        }
  
 	augeas { "Disable uncommon network protocols": 
 	               	context => "/files/etc/modprobe.d/CIS.conf",
 	               	changes => [
                	        "set install[. = 'dccp'] 'dccp'",
                	        "set install[. = 'dccp']/command '/bin/true'",
                	        "set install[. = 'sctp'] 'sctp'",
                	        "set install[. = 'sctp']/command '/bin/true'",
                	        "set install[. = 'rds'] 'rds'",
                	        "set install[. = 'rds']/command '/bin/true'",
                	        "set install[. = 'tipc'] 'tipc'",
               		        "set install[. = 'tipc']/command '/bin/true'"
               		];
        	}
	augeas { "Modify Network Parameters (Host Only)": 
                	context => "/files/etc/sysctl.conf",
                	lens    => "sysctl.lns",
                	incl    => "/etc/sysctl.conf",
                	changes => [
                	        "set net.ipv4.ip_forward 0",
                	        "set net.ipv4.conf.all.send_redirects 0",
                	        "set net.ipv4.conf.default.send_redirects 0"
                	];
        	}
}
