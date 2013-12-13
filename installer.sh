#!/bin/bash
# Viral Security
# https://github.com/viralsecurity/static-firewall
# Static firewall installer

PROD="static-firewall"
INSTALL_DIR=/etc/firewall
SYSV_DIR=/etc/init.d
USER=$(whoami)
SYMLINK=$(which ln)
COPY=$(which cp)
INSTALL_TIME=$(date +%s)

check_conflict()
{
  if [[ -d "/etc/apf" ]]; then
    die_gracefully "APF is already installed, please remove"
  fi
  if [[ -d "/etc/csf" ]]; then
    die_gracefully "CSF is already installed, please remove"
  fi
  if [[ -d "/etc/firewall" ]]; then
    bash upgrade.sh
	exit 0
  fi
}

die_gracefully()
{
  echo "Error: $*"
  exit 1
}

whitelist_listening_ports()
{
  local TCP_PORTS=$(netstat -napl | grep LISTEN | grep -v 127.0.0.1 | grep tcp | awk '{print $4}' | grep : | tr ':' ' ' | awk '{print $2}' | sort -n)
  for port in $TCP_PORTS; do
    find_service "$port" "tcp"
    echo "\$IPT -A INPUT -m tcp -p tcp --dport $port -j ACCEPT # $FIND_SERVICE" >> "$INSTALL_DIR/ports.ingress"
  done
  local UDP_PORTS=$(netstat -napl | grep -v 127.0.0.1 | grep udp | awk '{print $4}' | grep : | tr ':' ' ' | awk '{print $2}' | sort -n)
  for port in $UDP_PORTS; do
    find_service "$port" "udp"
    echo "\$IPT -A INPUT -m udp -p udp --dport $port -j ACCEPT # $FIND_SERVICE" >> "$INSTALL_DIR/ports.ingress"
  done
}

find_service()
{
  PORT=$1
  PROTO=$2
  FIND_SERVICE=$(egrep "\b$PORT/$PROTO\b" /etc/services | awk '{print $1}')
  if [[ -z "$FIND_SERVICE" ]]; then
    FIND_SERVICE="Unknown service"
  fi
}

install_firewall()
{
  CURPWD=$(pwd)
  mkdir -p -m 0700 "$INSTALL_DIR" "$INSTALL_DIR/acl" "$INSTALL_DIR/internal"
  rm -f "$SYSV_DIR/firewall"
  rm -f /usr/sbin/sfw
  rm -f /usr/sbin/firewall
  $COPY -f "$CURPWD/acl/firewall.deny" "$INSTALL_DIR/acl/"
  $COPY -f "$CURPWD/acl/firewall.trust" "$INSTALL_DIR/acl/"
  $COPY -f "$CURPWD/acl/firewall.remotes" "$INSTALL_DIR/acl/"
  $COPY -f "$CURPWD/acl/ports.ingress" "$INSTALL_DIR/acl/"
  $COPY -f "$CURPWD/acl/ports.egress" "$INSTALL_DIR/acl/"
  $COPY -f "$CURPWD/internal/functions.sh" "$INSTALL_DIR/internal/"
  chmod u+x "$CURPWD/internal/firewall.sh"
  $COPY -f "$CURPWD/internal/firewall.sh" "$SYSV_DIR/firewall"
  chown -R root:root "$INSTALL_DIR"
  $SYMLINK -s "$SYSV_DIR/firewall" /usr/sbin/sfw
  $SYMLINK -s "$SYSV_DIR/firewall" /usr/sbin/firewall 
  chown -h root:root /usr/sbin/sfw
  chown -h root:root /usr/sbin/firewall
}

activate_startup()
{
  if [[ -f "/etc/redhat-release" ]]; then
    echo "Redhat OS detected, activating automatic startup (chkconfig)"
    /sbin/chkconfig firewall on
  fi

  if [[ -f "/etc/debian_version" ]]; then
    echo "Debian OS detected, activating automatic startup (update-rc.d)"
    /usr/sbin/update-rc.d firewall defaults
  fi
}

post_install()
{
  echo ""
  echo "$PROD installed."
  echo ""
  echo "Please edit the following files before starting $PROD:"
  echo -e " Inbound rules:\t\t\t$INSTALL_DIR/ports.ingress"
  echo -e " Outbound rules:\t\t$INSTALL_DIR/ports.egress"
  echo -e " Inbound Trusted IPs:\t\t$INSTALL_DIR/firewall.trust"
  echo -e " Outbound Trusted IPs:\t\t$INSTALL_DIR/firewall.remotes"
  echo ""
  echo "To start $PROD, run $SYSV_DIR/firewall start"
}

if [[ "$USER" -ne 'root' ]]; then
  die_gracefully "$PROD must be installed as root"
fi

check_conflict
install_firewall
whitelist_listening_ports
activate_startup
post_install
