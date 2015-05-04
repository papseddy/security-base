class security::packageservice {

  $::package_absent [ "telnet-server","telnet","rsh-server","rsh","ypbind","ypserv","tftp","tftp-server", "talk","talk-server","xinetd","openldap-servers","openldap-clients","bind","vsftpd","httpd","dovecot","samba","squid","snmp" ]
  
  package { $::package_absent :
     ensure => absent;
        }

  $::service_false ["chargen-dgram","chargen-stream","daytime-dgram","daytime-stream","echo-dgram","echo-stream","tcpmux-server","avahi-daemon","cups","nfslock","rpcgssd","rpcbind","rpcidmapd","rpcsvcgssd" ]
  service { $::service_false :
    enable => false,
          ensure => stopped;
  }
}
