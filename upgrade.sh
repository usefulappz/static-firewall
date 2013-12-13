#!/bin/bash
# Viral Security
# https://github.com/viralsecurity/static-firewall
# Static firewall upgrade script

PROD="static-firewall"
INSTALL_DIR=/etc/firewall
SYSV_DIR=/etc/init.d
USER=$(whoami)
SYMLINK=$(which ln)
COPY=$(which cp)

die_gracefully()
{
  echo "Error: $*"
  exit 1
}

upgrade_firewall()
{
  if [ -d "$INSTALL_DIR" ]; then
  
    ORIG=$(date +%s)
    OLDFW=/etc/firewall.old-$ORIG
    mv /etc/firewall $OLDFW
    CURPWD=$(pwd)
	
    mkdir -p -m 0700 "$INSTALL_DIR"
	mkdir -p -m 0700 "$INSTALL_DIR/internal" "$INSTALL_DIR/acl"

    rm -f "$SYSV_DIR/firewall"
    rm -f /usr/sbin/firewall

    $COPY -f "$CURPWD/firewall.sh" "$SYSV_DIR/firewall"
    chmod 0100 "$INSTALL_DIR/firewall"

	# For versions where acls were in $INSTALL_DIR

    $COPY -f "$OLDFW/firewall.deny" "$INSTALL_DIR/acl/" &>/dev/null
    $COPY -f "$OLDFW/firewall.trust" "$INSTALL_DIR/acl/" &>/dev/null
    $COPY -f "$OLDFW/firewall.remotes" "$INSTALL_DIR/acl/" &>/dev/null
    $COPY -f "$OLDFW/ports.ingress" "$INSTALL_DIR/acl/" &>/dev/null
    $COPY -f "$OLDFW/ports.egress" "$INSTALL_DIR/acl/" &>/dev/null

	# For versions where acls are in $INSTALL_DIR/acl

	$COPY -f "$OLDFW/acl/firewall.deny" "$INSTALL_DIR/acl/" &>/dev/null
    $COPY -f "$OLDFW/acl/firewall.trust" "$INSTALL_DIR/acl/" &>/dev/null
    $COPY -f "$OLDFW/acl/firewall.remotes" "$INSTALL_DIR/acl/" &>/dev/null
    $COPY -f "$OLDFW/acl/ports.ingress" "$INSTALL_DIR/acl/" &>/dev/null
    $COPY -f "$OLDFW/acl/ports.egress" "$INSTALL_DIR/acl/" &>/dev/null

    $COPY -f "$CURPWD/functions.sh" "$INSTALL_DIR/internal/"
    chown -R root:root "$INSTALL_DIR"
    $SYMLINK -s "$INSTALL_DIR/firewall" /usr/sbin/firewall
    $SYMLINK -s /usr/sbin/firewall "$SYSV_DIR/firewall"
    chmod 0100 /usr/sbin/firewall
    chown -h root:root /usr/sbin/firewall
  else
    die_gracefully "Cannot upgrade firewall, use installer.sh instead"
  fi
}

post_install()
{
  echo ""
  echo "$PROD upgraded."
  echo ""
  echo "Restarting Firewall.."
  /etc/init.d/firewall stop
  /etc/init.d/firewall start
}

if [ "$USER" == "root" ]; then
else
  die_gracefully "$PROD must be installed as root"
fi

upgrade_firewall
post_install
