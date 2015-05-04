class security::users {

  user { "root": 
                gid => 0;
        }

        exec { "Set Default umask for Users - /etc/bashrc": 
                command => "/bin/sed -i -r 's/(umask)([ \t]*)[0-9]*/\\1\\2077/gi' /etc/bashrc",
                onlyif  => "/usr/bin/test `/bin/egrep -i '(umask|UMASK)[[:space:]]*[0-9]*' /etc/bashrc | /bin/egrep -v -i '(umask|UMASK)[[:space:]]*077' | /usr/bin/wc -w` -ne 0";
        }

        exec { "Set Default umask for Users - /etc/profile": 
                command => "/bin/sed -i -r 's/(umask)([ \t]*)[0-9]*/\\1\\2077/gi' /etc/profile",
                onlyif  => "/usr/bin/test `/bin/egrep -i '(umask|UMASK)[[:space:]]*[0-9]*' /etc/profile | /bin/egrep -v -i '(umask|UMASK)[[:space:]]*077' | /usr/bin/wc -w` -ne 0";
        }

        exec { "Lock Inactive User Accounts": 
                command => "useradd -D -f 35",
                onlyif  => "useradd -D | awk -F= '\$1 == \"INACTIVE\" && \$2 >= 35  { exit 1 }'",
        	path    => "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games",
	}
  
  file { "/etc/passwd": 
                owner  => "root",
                group  => "root",
                mode => '0644';
        }

        file { "/etc/shadow": 
                owner  => "root",
                group  => "root",
                mode => '000';
        }

        file { "/etc/gshadow": 
                owner  => "root",
                group  => "root",
                mode => '000';
        }

        file { "/etc/group": 
                owner  => "root",
                group  => "root",
                mode => '0644';
        }

  file { 
                "/etc/issue":
                        owner  => "root",
                        group  => "root",
                        mode   => '0644',
                        links  => "follow",
                        content => "Authorized uses only. All activity may be monitored and reported.";
                "/etc/issue.net":
                        owner  => "root",
                        group  => "root",
                        mode   => '0644',
                        links  => "follow",
                        content => "Authorized uses only. All activity may be monitored and reported.";
                "/etc/motd":
                        owner  => "root",
                        group  => "root",
                        mode   => '0644',
                        links  => "follow",
                        content => "Authorized uses only. All activity may be monitored and reported.";
        }
}
