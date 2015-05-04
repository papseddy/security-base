class security::postfix {
	
	augeas { "Configure Mail Transfer Agent for Local-Only Mode": 
                context => "/files/etc/postfix/main.cf",
                lens    => "postfix_main.lns",
                incl    => "/etc/postfix/main.cf",
                changes => "set inet_interfaces localhost",
                onlyif  => "get inet_interfaces != localhost";
        }
}
