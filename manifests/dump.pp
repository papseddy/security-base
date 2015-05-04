class security::dump {
  
  augeas {
                "Restrict Core Dumps - /etc/security/limits.conf": # CentOS 6 v1.0.0 1.6.1
                        context => "/files/etc/security/limits.conf",
                        lens    => "limits.lns",
                        incl    => "/etc/security/limits.conf",
                        changes => [
                                "set domain '*'",
                                "set domain/type hard",
                                "set domain/item core",
                                "set domain/value 0",
                        ];

                "Restrict Core Dumps - /etc/sysctl.conf": # CentOS 6 v1.0.0 1.6.1
                        context => "/files/etc/sysctl.conf",
                        lens    => "sysctl.lns",
                        incl    => "/etc/sysctl.conf",
                        changes => "set fs.suid_dumpable 0";
        }
  
  augeas { "Configure ExecShield and Enable Randomized Virtual Memory Region Placement": # CentOS 6 v1.0.0 1.6.2-1.6.3
                context => "/files/etc/sysctl.conf",
                lens    => "sysctl.lns",
                incl    => "/etc/sysctl.conf",
                changes => [
                        "set kernel.exec-shield 1",
                        "set kernel.randomize_va_space 2",
                ];
        }
}
