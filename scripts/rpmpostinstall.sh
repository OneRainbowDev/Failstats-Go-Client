#!/bin/bash
adduser --shell=/bin/false --no-create-home --system failstats
mkdir /var/lib/failstats/
chown failstats /var/lib/failstats/

systemctl daemon-reload
systemctl enable --now failstats.service
