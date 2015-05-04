class security::password {
 	case $operatingsystem {
  		'RedHat', 'CentOS': {
			exec { "Upgrade Password Hashing Algorithm to SHA-512": 
                		command => "/usr/sbin/authconfig --passalgo=sha512 --update",
                		onlyif  => "/usr/sbin/authconfig --test | /bin/grep hashing | /bin/grep -v sha512"
        		}

        		# NOTE: Fails to set options if pam_cracklib.so is entirely unconfigured.
       			augeas { "Set Password Creation Requirement Parameters Using pam_cracklib": 
                		context => "/files/etc/pam.d/system-auth",
                		changes => [
                		        "set *[type = 'password'][module = 'pam_cracklib.so']/control required",
                		        "set *[type = 'password'][module = 'pam_cracklib.so']/argument[. =~regexp('retry=.*')] retry=3",
                		        "set *[type = 'password'][module = 'pam_cracklib.so']/argument[. =~regexp('minlen=.*')] minlen=14",
                		        "set *[type = 'password'][module = 'pam_cracklib.so']/argument[. =~regexp('dcredit=.*')] dcredit=-1",
                		        "set *[type = 'password'][module = 'pam_cracklib.so']/argument[. =~regexp('ucredit=.*')] ucredit=-1",
                		        "set *[type = 'password'][module = 'pam_cracklib.so']/argument[. =~regexp('ocredit=.*')] ocredit=-1",
                		        "set *[type = 'password'][module = 'pam_cracklib.so']/argument[. =~regexp('lcredit=.*')] lcredit=-1",
                		]
        		}
  
  			# Set Lockout for Failed Password Attempts
        		augeas {
        		"Set Lockout for Failed Password Attempts - system-auth preauth":
          			context => "/files/etc/pam.d",
          			changes => [
                			"ins 01 after system-auth/*[type='auth'][module='pam_env.so']",
                        		"set system-auth/01/type auth",
                        		"set system-auth/01/control required",
                        		"set system-auth/01/module pam_faillock.so",
                        		"set system-auth/01/argument[1] preauth",
                        		"set system-auth/01/argument[2] audit",
                        		"set system-auth/01/argument[3] silent",
                        		"set system-auth/01/argument[4] deny=5",
                        		"set system-auth/01/argument[5] unlock_time=900",
                        	],
                        	onlyif  => "match system-auth/*[type='auth'][control='required'][module='pam_faillock.so'] size == 0";
  
  			"Set Lockout for Failed Password Attempts - system-auth pam_unix":
        			context => "/files/etc/pam.d",
                		changes => [
                			"set system-auth/*[type='auth'][module='pam_unix.so']/control '[success=1 default=bad]'"
                         	];

  			"Set Lockout for Failed Password Attempts - system-auth authfail":
    				context => "/files/etc/pam.d",
                		changes => [
                  			"ins 01 after system-auth/*[type='auth'][module='pam_unix.so']",
                        		"set system-auth/01/type auth",
                        		"set system-auth/01/control [default=die]",
                        		"set system-auth/01/module pam_faillock.so",
                        		"set system-auth/01/argument[1] authfail",
                        		"set system-auth/01/argument[2] audit",
                        		"set system-auth/01/argument[3] deny=5",
                        		"set system-auth/01/argument[4] unlock_time=900",
                        	],
                        	onlyif  => "match system-auth/*[type='auth'][control='[default=die]'][module='pam_faillock.so'] size == 0";
  
  			"Set Lockout for Failed Password Attempts - system-auth authsucc":
          			context => "/files/etc/pam.d",
                		changes => [
                			"ins 01 after system-auth/*[type='auth'][control='[default=die]'][module='pam_faillock.so']",
                        		"set system-auth/01/type auth",
                        		"set system-auth/01/control sufficient",
                        		"set system-auth/01/module pam_faillock.so",
                        		"set system-auth/01/argument[1] authsucc",
                        		"set system-auth/01/argument[2] audit",
                        		"set system-auth/01/argument[3] deny=5",
                        		"set system-auth/01/argument[4] unlock_time=900",
                        	],
                        	onlyif  => "match system-auth/*[type='auth'][control='sufficient'][module='pam_faillock.so'] size == 0";
  
  			"Set Lockout for Failed Password Attempts - password-auth preauth":
          			context => "/files/etc/pam.d",
                		changes => [
                  			"ins 01 after password-auth/*[type='auth'][module='pam_env.so']",
                        		"set password-auth/01/type auth",
                        		"set password-auth/01/control required",
                        		"set password-auth/01/module pam_faillock.so",
                        		"set password-auth/01/argument[1] preauth",
                        		"set password-auth/01/argument[2] audit",
                        		"set password-auth/01/argument[3] silent",
                        		"set password-auth/01/argument[4] deny=5",
                        		"set password-auth/01/argument[5] unlock_time=900",
                        	],
                        	onlyif  => "match password-auth/*[type='auth'][control='required'][module='pam_faillock.so'] size == 0";
  
  			"Set Lockout for Failed Password Attempts - password-auth pam_unix":
         			context => "/files/etc/pam.d",
                		changes => [
                  			"set password-auth/*[type='auth'][module='pam_unix.so']/control '[success=1 default=bad]'"
                        	];
  
  			"Set Lockout for Failed Password Attempts - password-auth authfail":
          			context => "/files/etc/pam.d",
                		changes => [
                  			"ins 01 after password-auth/*[type='auth'][module='pam_unix.so']",
                        		"set password-auth/01/type auth",
                        		"set password-auth/01/control [default=die]",
                        		"set password-auth/01/module pam_faillock.so",
                        		"set password-auth/01/argument[1] authfail",
                        		"set password-auth/01/argument[2] audit",
                        		"set password-auth/01/argument[3] deny=5",
                        		"set password-auth/01/argument[4] unlock_time=900",
                        	],
                        	onlyif  => "match password-auth/*[type='auth'][control='[default=die]'][module='pam_faillock.so'] size == 0";

  			"Set Lockout for Failed Password Attempts - password-auth authsucc":
    				context => "/files/etc/pam.d",
                		changes => [
                  			"ins 01 after password-auth/*[type='auth'][control='[default=die]'][module='pam_faillock.so']",
                        		"set password-auth/01/type auth",
                        		"set password-auth/01/control sufficient",
                        		"set password-auth/01/module pam_faillock.so",
                        		"set password-auth/01/argument[1] authsucc",
                        		"set password-auth/01/argument[2] audit",
                        		"set password-auth/01/argument[3] deny=5",
                        		"set password-auth/01/argument[4] unlock_time=900",
                        	],
                        	onlyif  => "match password-auth/*[type='auth'][control='sufficient'][module='pam_faillock.so'] size == 0";
  			}
  
  			augeas { "Limit Password Reuse": 
                		context => "/files/etc/pam.d/system-auth",
                		changes => "set *[type = 'password'][module = 'pam_unix.so']/argument[. =~regexp('remember=.*')] remember=5"
        		}
       		}
		
		'Ubuntu' : {
			augeas { "Upgrade Password Hashing Algorithm to SHA-512":
				context => "/files/etc/pam.d",
				changes => [
					"ins 01 after common-password/*[type='password'][module='pam_unix.so']",
                                        "set common-password/01/type password",
                                        "set common-password/01/control [success=1 default=ignore]",
                                        "set common-password/01/module pam_unix.so",
                                        "set common-password/01/argument[1] obscure",
                                        "set common-password/01/argument[2] sha512",
					"set common-password/01/argument[3] minlen=12",
					"set common-password/01/argument[4] retry=3",
					"set common-password/01/argument[5] dcredit=-1",
					"set common-password/01/argument[6] ucredit=-1",
					"set common-password/01/argument[7] ocredit=-1",
					"set common-password/01/argument[8] lcredit=-1",
				];
			}
			
			augeas { "Upgrade Password Hashing Algorithm to SHA-512 ":
				context => "/files/etc/login.defs",
				changes => "set ENCRYPT_METHOD SHA512",
			}
			
			augeas {
                        "Set Lockout for Failed Password Attempts - system-auth preauth":
                                context => "/files/etc/pam.d",
                                changes => [
                                        "ins 01 after common-auth/*[type='auth'][module='pam_env.so']",
                                        "set common-auth/01/type auth",
                                        "set common-auth/01/control required",
                                        "set common-auth/01/module pam_tally2.so",
                                        "set common-auth/01/argument[1] preauth",
                                        "set common-auth/01/argument[2] audit",
                                        "set common-auth/01/argument[3] silent",
                                        "set common-auth/01/argument[4] deny=5",
                                        "set common-auth/01/argument[5] unlock_time=900",
                                ],
                                onlyif  => "match common-auth/*[type='auth'][control='required'][module='pam_tally2.so'] size == 0";
			
			"Set Lockout for Failed Password Attempts - system-auth pam_unix":
                                context => "/files/etc/pam.d",
                                changes => [
                                        "set common-auth/*[type='auth'][module='pam_unix.so']/control '[success=1 default=bad]'"
                                ];
			
			"Set Lockout for Failed Password Attempts - system-auth authfail":
                                context => "/files/etc/pam.d",
                                changes => [
                                        "ins 01 after common-auth/*[type='auth'][module='pam_unix.so']",
                                        "set common-auth/01/type auth",
                                        "set common-auth/01/control [default=die]",
                                        "set common-auth/01/module pam_tally2.so",
                                        "set common-auth/01/argument[1] authfail",
                                        "set common-auth/01/argument[2] audit",
                                        "set common-auth/01/argument[4] deny=5",
                                        "set common-auth/01/argument[5] unlock_time=900",
                                ],
                                onlyif  => "match common-auth/*[type='auth'][control='[default=die]'][module='pam_tally2.so'] size == 0";

			"Set Lockout for Failed Password Attempts - system-auth authsucc":
                                context => "/files/etc/pam.d",
                                changes => [
                                        "ins 01 after common-auth/*[type='auth'][control='[default=die]'][module='pam_tally2.so']",
                                        "set common-auth/01/type auth",
                                        "set common-auth/01/control sufficient",
                                        "set common-auth/01/module pam_tally2.so",
                                        "set common-auth/01/argument[1] authsucc",
                                        "set common-auth/01/argument[2] audit",
                                        "set common-auth/01/argument[4] deny=5",
                                        "set common-auth/01/argument[5] unlock_time=900",
                                ],
                                onlyif  => "match common-auth/*[type='auth'][control='sufficient'][module='pam_tally2.so'] size == 0";

			}
		}	
		}
		augeas { "Limit Password Reuse": 
                	context => "/files/etc/pam.d/system-auth",
                        changes => "set *[type = 'password'][module = 'pam_unix.so']/argument[. =~regexp('remember=.*')] remember=5"
		}
        
                augeas { "Restrict Access to the su Command": 
                	context => "/files/etc/pam.d/",
                        changes => [
                	        "ins 01 after su/*[last()]",
                                "set su/01/type auth",
                                "set su/01/control required",
                                "set su/01/module pam_wheel.so",
                                "set su/01/argument use_uid",
                        ],
                        onlyif  => "match su/*[type='auth'][control='required'][module='pam_wheel.so'] size == 0";
		}       
  
                augeas { "Set Shadow Password Suite Parameters (/etc/login.defs)": 
                        context => "/files/etc/login.defs",
                        lens    => "login_defs.lns",
                        incl    => "/etc/login.defs",
                        changes => [
                	        "set PASS_MAX_DAYS 90",
                                "set PASS_MIN_DAYS 7",
                                "set PASS_WARN_AGE 7",
                        ];
		}
	}

