class security::ntp {

  	package { "ntp":
                ensure => present;
        }
        
        augeas {
                "Configure Network Time Protocol (NTP) - Add ipv4 default restrict":
                        context => "/files/etc/ntp.conf",
                        changes => [
                                "ins restrict after restrict[last()]",
                                "set restrict[last()] default"
                        ],
                        onlyif  => "match /files/etc/ntp.conf/restrict[. = 'default'][count(ipv6) = 0] size == 0";

                "Configure Network Time Protocol (NTP) - Add ipv6 default restrict":
                        context => "/files/etc/ntp.conf",
                        changes => [
                                "ins restrict after restrict[last()]",
                                "set restrict[last()] default",
                                "clear restrict[last()]/ipv6"
                        ],
                        onlyif  => "match /files/etc/ntp.conf/restrict[. = 'default']/ipv6 size == 0";

    		"Configure Network Time Protocol (NTP) - Set all default restricted actions":
                        context => "/files/etc/ntp.conf",
                        changes => [
                                "setm restrict[. = 'default'] action[1] kod",
                                "setm restrict[. = 'default'] action[2] nomodify",
                                "setm restrict[. = 'default'] action[3] notrap",
                                "setm restrict[. = 'default'] action[4] nopeer",
                                "setm restrict[. = 'default'] action[5] noquery"
                        ];
        }
}
