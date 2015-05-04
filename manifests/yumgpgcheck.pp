class security::yumgpgcheck {

  augeas { "Verify that gpgcheck is Globally Activated": # CentOS 6 v1.0.0 1.2.2
                context => "/files/etc/yum.conf",
                lens    => "yum.lns",
                incl    => "/etc/yum.conf",
                changes => "set main/gpgcheck 1";
        }
}
