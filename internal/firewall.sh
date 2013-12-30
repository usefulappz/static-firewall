#!/bin/bash
# chkconfig: 3 20 80
# description: Static Firewall
### BEGIN INIT INFO
# Provides:				firewall
# Required-Start:		$syslog $local_fs $network
# Required-Stop:		$syslog $local_fs $network
# Default-Start:		3
# Default-Stop:			0 1 6
# Short-Description:	Static Firewall for non-DHCP servers
### END INIT INFO

IPT=$(which iptables)
FWPATH=/etc/firewall

TRUST_IPS=`cat $FWPATH/acl/firewall.trust`
DENY_IPS=`cat $FWPATH/acl/firewall.deny`
REMOTE_IPS=`cat $FWPATH/acl/firewall.remotes`

source "$FWPATH/internal/functions.sh"

case "$1" in

  start)
    fwstart
  ;;

  stop)
    fwstop
  ;;

  restart)
    fwstop
    fwstart
  ;;

  status)
    iptables -vnL
    exit 0
  ;;
  
  logs)
    if [[ -z "$2" ]]; then
      echo "usage: $0 logs <ip>"
	  exit 3
	else
      IP="$2"
	  nice -n10 zgrep "$IP" \
	  /var/log/messages* \
	  /var/log/secure* \
	  /var/log/auth* \
	  /var/log/nginx/*error* \
	  /var/log/apache2/*error* \
	  /usr/local/apache/logs/error_log*
	  /usr/local/apache/logs/modsec_* 2>/dev/null | less	  
    fi
  ;;

  reload)
    exit 3
  ;;

  force-reload)
    exit 3
  ;;

  deny|block)
    if [[ -z "$2" ]]; then
      echo ">> usage: $0 deny <ip>"
      exit 2
    fi
    if grep -Fxq "$2" "$FWPATH/acl/firewall.trust"; then
	  del_trust "$2"
    fi
	if ! grep -Fxq "$2" "$FWPATH/acl/firewall.deny"; then
	  add_blackhole "$2"
	fi
  ;;

  undeny|unblock)
    if [[ -z "$2" ]]; then
      echo ">> usage: $0 undeny <ip>"
      exit 2
    fi
	if grep -Fxq "$2" "$FWPATH/acl/firewall.deny"; then
      del_blackhole "$2"
    fi
  ;;

  allow|trust)
    if [[ -z "$2" ]]; then
      echo ">> usage: $0 allow <ip>"
      exit 2
    fi
    # Implies to remove from blackhole, add to trust
    if grep -Fxq "$2" "$FWPATH/acl/firewall.deny"; then
      del_blackhole "$2"
	fi
	if ! grep -Fxq "$2" "$FWPATH/acl/firewall.trust"; then
	  add_trust "$2"
	fi
    exit 0
  ;;

  unallow|untrust)
    if [[ -z "$2" ]]; then
      echo ">> usage: $0 unallow <ip>"
      exit 2
    fi
    if grep -Fxq "$2" "$FWPATH/acl/firewall.trust"; then
      del_trust "$2"
    fi
  ;;

  *)
    echo "usage: $0 <logs|start|stop|restart|[[un]deny|[un]allow <ip>]>"
	echo "		 logs	 - show matching logs from <ip>"
    echo "       start   - enables firewall"
    echo "       stop    - disables firewall"
    echo "       restart - stop then start again"
    echo "       deny    - drop traffic from <ip>"
    echo "       undeny  - undo drop traffic from <ip>"
    echo "       allow   - exempt <ip> from firewall protection"
    echo "       unallow - undo exempt <ip> from firewall protection"
    exit 3
  ;;
esac

