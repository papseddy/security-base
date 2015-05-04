class security::selinux {
  augeas { "Enable SELinux in /etc/grub.conf": 
                context => "/files/etc/grub.conf",
                lens    => "grub.lns",
                incl    => "/etc/grub.conf",
                changes =>  [
                        "rm title[*]/kernel/selinux[.='0']",
                        "rm title[*]/kernel/enforcing[.='0']"
                ];
        }

        augeas { "Set the SELinux State": 
                context => "/files/etc/sysconfig/selinux",
                lens    => "shellvars.lns",
                incl    => "/etc/sysconfig/selinux",
                changes => [
                        "set SELINUX enforcing"
                ];
        }

        augeas { "Set the SELinux Policy": 
                context => "/files/etc/sysconfig/selinux",
                lens    => "shellvars.lns",
                incl    => "/etc/sysconfig/selinux",
                changes => [
                        "set SELINUXTYPE targeted"
                ];
        }
  
  package {
                "setroubleshoot":
                        ensure => absent;
                "mcstrans": 
                        ensure => absent;
        }
}