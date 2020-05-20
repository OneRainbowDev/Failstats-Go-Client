#!/bin/bash
adduser --shell=/bin/false --no-create-home --gecos "" --system --disabled-password
mkdir /var/lib/failstats/
chown failstats /var/lib/failstats/

systemctl daemon-reload
systemctl enable --now failstats.service
