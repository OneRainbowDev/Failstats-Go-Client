#!/bin/bash
adduser --shell=/bin/false --no-create-home --system --disabled-password failstats
mkdir /var/lib/failstats/
chown failstats /var/lib/failstats/

systemctl daemon-reload
systemctl enable --now failstats.service
