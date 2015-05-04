class security::grub {

	case $operatingsystem {
  		'RedHat', 'CentOS': {
			file { "/etc/grub.conf": 
                		owner => "root",
                		group => "root",
                		links => "follow",
                		mode  => '0600';
        		}
  
   			augeas { "Require authentication for single-user mode": # CentOS 6 v1.0.0 1.5.4-1.5.5
                		context => "/files/etc/sysconfig/init",
                		changes => [
                		        "set SINGLE /sbin/sulogin",
                        		"set PROMPT no"
                		];
        		}

		}
		
		'Ubuntu' : {
			file { "/etc/default/grub":
				owner => "root",
	                        group => "root",
                                links => "follow",
                                mode  => '0600';
                        }
			
			augeas { "Require authentication for single-user mode" :
				context => "/files/etc/default/grub",
				changes	=> [
					"set GRUB_DISABLE_RECOVERY true",
				];
			}

			exec { "Updating Grub Confirguration":
				path    => "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games",
				user	=> "root",
				command	=> "update-grub"
			}
		}
	}
}
