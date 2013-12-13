die_gracefully()
{
  echo "ERROR: $*"
  exit 1
}

add_blackhole()
{
  bIP=$1
  if grep -Fxq "$bIP" "$FWPATH/firewall.deny"; then
    die_gracefully "$bIP is already blackholed"
	exit 1
  else
    $IPT -I BLACKHOLE -s $bIP -j DROP &>/dev/null
    $IPT -I BLACKHOLE -d $bIP -j DROP &>/dev/null
    echo $bIP >> $FWPATH/firewall.deny
    echo "* Blackholed $bIP"
  fi
}

del_blackhole()
{
  bIP=$1
  $IPT -D BLACKHOLE -s $bIP -j DROP &>/dev/null
  $IPT -D BLACKHOLE -d $bIP -j DROP &>/dev/null
  grep -v "$bIP" "$FWPATH/firewall.deny" > "$FWPATH/firewall.deny"
  echo "* Removed blackhole for $bIP"
}

add_trust()
{
  tIP=$1
  if grep -Fxq "$tIP" "$FWPATH/firewall.trust"; then
    echo "$tIP is already trusted."
  else
    $IPT -I TRUST -s $tIP -j ACCEPT &>/dev/null
    $IPT -I TRUST -d $tIP -j ACCEPT &>/dev/null
    echo $tIP >> $FWPATH/firewall.trust
    echo "* Trusted $tIP"
  fi
}

del_trust()
{
  tIP=$1
  $IPT -D TRUST -s $tIP -j ACCEPT &>/dev/null
  $IPT -D TRUST -d $tIP -j ACCEPT &>/dev/null
  grep -v "$tIP" "$FWPATH/firewall.trust" > "$FWPATH/firewall.trust"
  echo "* Untrusted $tIP"
}

fwstart()
{

  echo -n "Firewall starting"

  # Clear Everything
  $IPT -P INPUT ACCEPT
  $IPT -P OUTPUT ACCEPT
  $IPT -P FORWARD ACCEPT
  $IPT -X &>/dev/null
  $IPT -Z &>/dev/null
  $IPT -F &>/dev/null

  echo -n "."
  # Attack Logging
  $IPT -N LOGATTACK &>/dev/null
  $IPT -A LOGATTACK -j LOG --log-level info --log-prefix "FW_ATTACK "
  $IPT -A LOGATTACK -j DROP

  # Drop chain
  $IPT -N BLACKHOLE &>/dev/null
  $IPT -A BLACKHOLE -j DROP

  # Trusted Chain
  $IPT -N TRUST &>/dev/null
  $IPT -A TRUST -j ACCEPT

  # Logdrop chain
  $IPT -N LOGDROP &>/dev/null
  $IPT -A LOGDROP -j LOG --log-level info --log-prefix "FW_LOGDROP "
  $IPT -A LOGDROP -j DROP

  # Logdrop chain (outbound)
  $IPT -N LOGDROPOUT &>/dev/null
  $IPT -A LOGDROPOUT -j LOG --log-level info --log-prefix "FW_EGRESS "
  $IPT -A LOGDROPOUT -j DROP

  # SYN Protection
  $IPT -N SYNFLOOD &>/dev/null
  $IPT -A SYNFLOOD -m limit --limit 175/s --limit-burst 200 -j RETURN
  $IPT -A SYNFLOOD -j LOGATTACK

  echo -n "."
  # Begin ruleset
  $IPT -A INPUT -i lo -j ACCEPT

  # Blackhole Banned IPs
  for bIP in $DENY_IPS; do
    $IPT -I INPUT  -s $bIP -j BLACKHOLE
    $IPT -I OUTPUT -d $bIP -j BLACKHOLE
  done

  # Trusted IPs
  for aIP in $TRUST_IPS; do
    $IPT -I INPUT  -s $aIP -j TRUST
    $IPT -I OUTPUT -d $aIP -j TRUST
  done

  $IPT -I INPUT  -s 0.0.0.0   -j BLACKHOLE	  # ignore broadcasts
  $IPT -I OUTPUT -d 224.0.0.0/24 -j BLACKHOLE	  # ignore multicast
  $IPT -I OUTPUT -p udp --dport 67 -j BLACKHOLE   # ignore dhcp
  $IPT -I INPUT -p udp --dport 137 -j BLACKHOLE	  # ignore netbios
  $IPT -I INPUT -p udp --dport 138 -j BLACKHOLE	  # ignore netbios
  $IPT -I INPUT -p udp --dport 17500 -j BLACKHOLE # ignore dropbox

  # Traverse important chains first
  $IPT -A INPUT -p tcp --syn -j SYNFLOOD
  $IPT -A INPUT -f -j LOGDROP                            # Fragmented Packets
  $IPT -A INPUT -p tcp --tcp-flags ALL ALL -j LOGATTACK  # XMAS Packets
  $IPT -A INPUT -p tcp --tcp-flags ALL NONE -j LOGATTACK # NULL Packets

  # Bad Flags
  $IPT -A INPUT -p tcp --tcp-flags ALL RST,ACK,PSH -j BLACKHOLE
  $IPT -A INPUT -p tcp --tcp-flags ALL RST,ACK,URG -j BLACKHOLE
  $IPT -A INPUT -p tcp --tcp-flags ALL RST,ACK,PSH,URG -j BLACKHOLE
  $IPT -A INPUT -p tcp --tcp-flags ALL FIN,PSH,ACK,URG -j BLACKHOLE
  $IPT -A INPUT -p tcp --tcp-flags ALL ACK,URG -j BLACKHOLE
  $IPT -A INPUT -p tcp --tcp-flags ALL ACK,URG,FIN -j BLACKHOLE

  # Stateful
  $IPT -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

  echo -n "."
  # Open Services
  source $FWPATH/ports.ingress

  # Log drop everything else
  $IPT -A INPUT -j LOGDROP

  #Outbound chain
  $IPT -A OUTPUT -o lo -p all -j ACCEPT
  $IPT -A OUTPUT -m state --state RELATED,ESTABLISHED -j ACCEPT

  # Allow outbound DNS
  # via /etc/resolv.conf resolvers only
  RESOLVERS=`awk '{if ($1 ~ /^nameserver/) print $2}' /etc/resolv.conf`
  for res in $RESOLVERS; do
    $IPT -A OUTPUT -m state --state NEW -p udp --dport 53 -d $res -j ACCEPT
    $IPT -A OUTPUT -m state --state NEW -p tcp --dport 53 -d $res -j ACCEPT
  done

  # Trusted Remotes
  for rIP in $REMOTE_IPS; do
    $IPT -I OUTPUT -d $rIP -j ACCEPT
  done

  echo -n "."
  # Egress Pinholes
  source $FWPATH/ports.egress

  # Log traffic not matching any above rules egressing your firewall
  $IPT -A OUTPUT -j LOGDROPOUT
  echo -en "\tOK\n"
}

fwstop()
{
  $IPT -X LOGDROP &>/dev/null
  $IPT -X LOGDROPOUT &>/dev/null
  $IPT -X BLACKHOLE &>/dev/null
  $IPT -X SYNFLOOD &>/dev/null
  $IPT -X LOGATTACK &>/dev/null
  $IPT -X TRUST &>/dev/null
  $IPT -Z &>/dev/null
  $IPT -P INPUT ACCEPT
  $IPT -P OUTPUT ACCEPT
  $IPT -P FORWARD ACCEPT
  $IPT -F &>/dev/null
  echo "Firewall stopped."
}
