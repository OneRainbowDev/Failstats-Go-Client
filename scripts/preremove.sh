#!/bin/bash
systemctl stop failstats.service
systemctl disable failstats.service
userdel failstats
