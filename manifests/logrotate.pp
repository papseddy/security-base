class security::logrotate {
 
	case $operatingsystem { 
		'RedHat', 'CentOS': {
				logrotate_file{"/var/log/messages":}
       				logrotate_file{"/var/log/secure":}
       				logrotate_file{"/var/log/maillog":}
        
			        define logrotate_file ( )
        			{
                			augeas{ "Configure Logrotate - $name":
                        				context => "/files/etc/logrotate.d/syslog",
                        				lens    => "logrotate.lns",
                        				incl    => "/etc/logrotate.d/syslog",
                        				changes => [    "ins file before rule/file[1]",
                        					        "set rule/file[1] $name",
                        					],
                        				onlyif =>"match *[file='$name'] size == 0",
                			}
        			}
		}	
		'Ubuntu'	: {
				logrotate_file{"/var/log/dmesg":}
                                logrotate_file{"/var/log/auth.log":}
                                logrotate_file{"/var/log/mail.log":}
			
				define	logrotate_file ( )
				{
					augeas{ "Configure Logrotate - $name":
                                                        context => "/files/etc/logrotate.d/rsyslog",
                                                        lens    => "logrotate.lns",
                                                        incl    => "/etc/logrotate.d/rsyslog",
                                                        changes => [    "ins file before rule/file[1]",
                                                                        "set rule/file[1] $name",
                                                                ],      
                                                        onlyif =>"match *[file='$name'] size == 0",
                                        }
				}
		}

	}
}		
