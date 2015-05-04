class security::aide {
  package { "aide": 
                ensure => installed;
        }

        exec { "Initialize AIDE" : 
                command => "aide --init -B 'database_out=file:/var/lib/aide/aide.db.gz'",
                creates => "/var/lib/aide/aide.db.gz",
                user    => "root",
                path	=> "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games",
		timeout => "-1",
                require => Package["aide"];
        }

        cron { "Implement Periodic Execution of File Integrity": 
                command => "aide --check",
                user    => "root",
                hour    => 5,
                minute  => 0,
                require => Package["aide"];
        }
}
