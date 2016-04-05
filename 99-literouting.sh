#!/bin/sh

if ([ "$ACTION" = ifup ] && [ "$INTERFACE" = PPTP ]); then
  python /etc/literouting/literouting.py
fi