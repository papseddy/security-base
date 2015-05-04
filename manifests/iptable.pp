class security::iptable {
	case $operatingsystem {
  		'RedHat', 'CentOS': {
 			service { "iptables": 
                        	enable => true,
                        	ensure => running;
        		}
		}
		
		'Ubuntu' : {
			service { "ufw":
				enable => true,
                                ensure => running;
                        }
                }
	}
}
