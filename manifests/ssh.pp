class security::ssh {
  
  augeas { "sshd config": 
                context => "/files/etc/ssh/sshd_config",
                lens    => "sshd.lns",
                incl    => "/etc/ssh/sshd_config",
                changes => [
                        "set Protocol 2",
                        "set LogLevel INFO",
                        "set X11Forwarding no",
                        "set MaxAuthTries 4",
                        "set IgnoreRhosts yes",
                        "set HostbasedAuthentication no",
                        "set PermitRootLogin no",
                        "set PermitEmptyPasswords no",
                        "set PermitUserEnvironment no",
                        "set ClientAliveInterval 300",
                        "set ClientAliveCountMax 0",
                        "set Banner /etc/issue.net",
                ],
        }
  
  file { "/etc/ssh/sshd_config": # CentOS 6 v1.0.0 6.2.3
                owner  => "root",
                group  => "root",
                links  => "follow",
                mode   => '0600';
        }
}
