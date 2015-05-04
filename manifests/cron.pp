class security::cron {
  
	case $operatingsystem {
		'Ubuntu': {
				package { "anacron": 
                			ensure => present,
        			}
	
				service { "cron":
					enable	=> true,
					ensure	=> running,
				}
			}
			
	'RedHat', 'CentOS': {
				package { "cronie-anacron":
					ensure => present;
				}
        			
				service {
                			"crond": 
                        		enable => true,
                        		ensure => running;
        			}
			}
	}

	file {
                "/etc/anacrontab": 
                        owner => "root",
                        group => "root",
                        links => "follow",
                        mode  => 600;
                "/etc/crontab": 
                        owner => "root",
                        group => "root",
                        links => "follow",
                        mode  => 600;
                "/etc/cron.hourly": 
                        owner => "root",
                        group => "root",
                        links => "follow",
                        mode  => 600;
                "/etc/cron.daily":  
                        owner => "root",
                        group => "root",
                        links => "follow",
                        mode  => 600;
                "/etc/cron.weekly": 
                        owner => "root",
                        group => "root",
                        links => "follow",
                        mode  => 600;
	"/etc/cron.monthly": 
                        owner => "root",
                        group => "root",
                        links => "follow",
                        mode  => 600;
                "/etc/cron.d": 
                        owner => "root",
                        group => "root",
                        links => "follow",
                        mode  => 600;
                "/etc/at.deny": 
                        ensure => absent;
                "/etc/at.allow":
                        ensure => present,
                        owner  => "root",
                        group  => "root",
                        links  => "follow",
                        mode   => 600;
                "/etc/cron.deny": 
                        ensure => absent;
                "/etc/cron.allow":
                        ensure => present,
                        owner  => "root",
                        group  => "root",
                        links  => "follow",
                        mode   => 600;
        }
	
}
