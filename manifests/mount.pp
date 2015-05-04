class security::mount {
  
  set_mount_option {
                "Ensure nodev option set on /tmp partition": file => "/tmp", option => "nodev"; 
                "Ensure nosuid option set on /tmp partition": file => "/tmp", option => "nosuid"; 
                "Ensure noexec option set on /tmp partition": file => "/tmp", option => "noexec"; 
                "Ensure nodev option set on /home partition": file => "/home", option => "nodev"; 
                "Ensure nodev option set on /dev/shm partition": file => "/dev/shm", option => "nodev"; 
                "Ensure nosuid option set on /dev/shm partition": file => "/dev/shm", option => "nosuid"; 
                "Ensure noexec option set on /dev/shm partition": file => "/dev/shm", option => "noexec"; 
        }

        define set_mount_option($file,$option) {
                augeas { "fstab-${file}-$option":
                        context => "/files/etc/fstab/*[file = '$file'][count(opt[. = '$option']) = 0]",
                        lens    => "fstab.lns",
                        incl    => "/etc/fstab",
                        changes => [
                                "ins opt after opt[last()]",
                                "set opt[last()] $option"
                        ],
                        onlyif  => "match /files/etc/fstab/*[file = '$file'][count(opt[. = '$option']) = 0] size > 0";
                }
        }
  
  mount { "Ensure /var/tmp is bound to /tmp": 
                name    => "/var/tmp",
                ensure  => mounted,
                atboot  => true,
                device  => "/tmp",
                fstype  => "none",
                options => "bind";
        }

  exec { "Set Sticky Bit on All World-Writable Directories": 
                        command => "/bin/df --local -P | /bin/awk {'if (NR!=1) print \$6'} | /bin/xargs -I '{}' /bin/find '{}' -xdev -type d \\( -perm -0002 -a ! -perm -1000 \\) 2>/dev/null | /bin/xargs /bin/chmod a+t",
                        onlyif  => "/bin/df --local -P | /bin/awk {'if (NR!=1) print \$6'} | /bin/xargs -I '{}' /bin/find '{}' -xdev -type d \\( -perm -0002 -a ! -perm -1000 \\) 2>/dev/null | /bin/egrep '.*'"
        }

        augeas { "Disable Mounting of various Filesystems": 
                context => "/files/etc/modprobe.d/CIS.conf",
                changes => [
                        "set install[. = 'cramfs'] 'cramfs'",
                        "set install[. = 'cramfs']/command '/bin/true'",
                        "set install[. = 'freevxfs'] 'freevxfs'",
                        "set install[. = 'freevxfs']/command '/bin/true'",
                        "set install[. = 'jffs2'] 'jffs2'",
                        "set install[. = 'jffs2']/command '/bin/true'",
                        "set install[. = 'hfs'] 'hfs'",
                        "set install[. = 'hfs']/command '/bin/true'",
                        "set install[. = 'hfsplus'] 'hfsplus'",
                        "set install[. = 'hfsplus']/command '/bin/true'",
                        "set install[. = 'squashfs'] 'squashfs'",
                        "set install[. = 'squashfs']/command '/bin/true'",
                        "set install[. = 'udf'] 'udf'",
                        "set install[. = 'udf']/command '/bin/true'"
                ]
        }
}
