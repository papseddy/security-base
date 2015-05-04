class security::audit {

	case $operatingsystem {
  	
		'RedHat', 'CentOS': {
  			package { "audit": 
				ensure => 'installed',
			}
	
  			augeas { "Enable Auditing for Processes That Start Prior to auditd": # CentOS 6 v1.0.0 4.2.3
                		context => "/files/etc/grub.conf",
                		lens    => "grub.lns",
                		incl    => "/etc/grub.conf",
                		changes =>  [
                		        "setm title[*]/kernel audit 1",
                		];
        		}
		}
        
		'Ubuntu' : {
			package { 'auditd': ensure => 'installed' }
			
			augeas { "Enable Auditing for Processes That Start Prior to auditd" :
				context => "/files/etc/default/grub",
				changes	=> [
					"set GRUB_CMDLINE_LINUX audit=1",
				];
			}

			exec { "Updating Grub Confirguration":
				path    => "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games",
				user	=> "root",
				command	=> "update-grub"
			}

		}
  	}
	augeas {"Disable System on Audit Log Full" : # CentOS 6 v1.0.0 4.2.1.2
                context => "/files/etc/audit/auditd.conf",
                changes => [
                        "set space_left_action email",
                        "set action_mail_acct root",
                        "set admin_space_left_action halt"
                ]
        }

        augeas { "Keep All Auditing Information": # CentOS 6 v1.0.0 4.2.1.3
                        context => "/files/etc/audit/auditd.conf",
                        changes => "set max_log_file_action keep_logs"
        }
        
        service { "auditd": # CentOS 6 v1.0.0 4.2.2
                enable => true,
                ensure => running;
        }

        file { "/etc/audit/audit.rules": # CentOS 6 v1.0.0 4.2.4-18
                owner   => "root",
                group   => "root",
                mode    => '0600',
                source  => $architecture? {
                        x64     => "puppet:///modules/security/audit.rules.64",
                        default => "puppet:///modules/security/audit.rules.386",
                }
        }
}
