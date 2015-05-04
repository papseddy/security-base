class security::rsyslog {
		
	package { "rsyslog": 
                ensure => present;
        }

        service { 
    		"syslog":
                        enable => false,
                        ensure => stopped;
                "rsyslog":
                        enable => true,
                        ensure => running;
        }

  	exec { "Create and Set Permissions on rsyslog Log Files - touch files":
                command => "awk '/^ *[^#$]/ { print $2 }' /etc/rsyslog.conf | egrep -o '/.*' | xargs -n 1 touch -a",
		path	=> "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games",		
        }

        exec { "Create and Set Permissions on rsyslog Log Files - chown files":
                command => "awk '/^ *[^#$]/ { print $2 }' /etc/rsyslog.conf | egrep -o '/.*' | xargs -n 1 chown root:root",
		path	=> "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games",
        }

        exec { "Create and Set Permissions on rsyslog Log Files - chmod files":
                command => "awk '/^ *[^#$]/ { print $2 }' /etc/rsyslog.conf | egrep -o '/.*' | xargs -n 1 chmod og-rwx",
		path	=> "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games",
        }
}
