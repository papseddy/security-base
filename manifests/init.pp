# Class: security
#
# This module manages security
#
# Parameters: none
#
# Actions:
#
# Requires: see Modulefile
#
# Sample Usage:
#
class security {
        
        include security::aide
        include security::audit
        include security::cron
        include security::dump
        include security::graphic
        include security::grub
        include security::iptable
        include security::logrotate
        include security::mount
        include security::network
        include security::ntp
        include security::packageservice
        include security::password
        include security::postfix
        include security::rsyslog
        include security::selinux
        include security::ssh
        include security::users
        include security::yumgpgcheck

}
