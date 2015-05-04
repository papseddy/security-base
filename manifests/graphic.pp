class security::graphic {

	case $operatingsystem {	
		'RedHat', 'CentOS': {
				augeas { "Set Daemon umask": 
                				context => "/files/etc/sysconfig/init",
                				lens    => "shellvars.lns",
                				incl    => "/etc/sysconfig/init",
                				changes => "set UMASK 027";
        				}
		
       	 			exec { "Remove X Windows": 
                				onlyif  => "/usr/bin/yum grouplist \"X Window System\" | /bin/grep 'Installed Groups'",
                				command => "/usr/bin/yum groupremove \"X Window System\"";
				}
			}
		'Ubuntu'	: {
				package { "xserver-xorg-core" :
						ensure	=> absent;
				}
			}
	}
}	
