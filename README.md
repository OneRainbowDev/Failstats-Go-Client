# FailStats
A very common tool to prevent brute force attacks on web facing services is [fail2ban](https://www.fail2ban.org/wiki/index.php/Main_Page), which bans ips if they attempt to access a secured service and fail too many times. This project is an attempt to make a ban tracker site [failstats.net](https://failstats.net).

This tool monitors the fail2ban log, reporting data to the failstats.net api. 

## Todo:
- Privacy Policy
- Intro?
- Configuration
- Build instructions

## Install Instructions:
Requires fail2ban to be installed and configured to be of use! :)

Signed failstats packages are hosted at [engiedev.net](https://engiedev.net).

### apt based systems:
- ``curl -s https://engiedev.net/release-key | sudo apt-key add``

- For Ubuntu based systems: ``add-apt-repository "deb https://apt.engiedev.net ubuntu main"``

- For Debian based systems: ``echo "deb https://apt.engiedev.net/ debian main" | sudo tee /etc/apt/sources.list.d/engiedev.list``

- ``sudo apt update``

- ``sudo apt install failstats``

### rpm systems:
The yum/dnf commands are interchangable.

- ``rpm --import https://engiedev.net/rpm-release-key``

- ``sudo yum-config-manager --add-repo https://rpm.engiedev.net/general/engiedev_general.repo``

- ``sudo yum update``

- ``sudo yum install failstats``

### Other systems:
- Download the failstats binary for your platform from [downloads.engiedev.net](https://downloads.engiedev.net) to an appropriate location, such as ``/usr/local/bin/``

- Download the [sample configuration file](failstats.conf) from the git repository to ``/etc/failstats.conf``

- Optionally download the service file for systemd to ``/etc/systemd/system/failstats.service`` and tweak to match your personal setup

- Run the binary or systemd service (systemd is recommended since it automatically starts when server reboots)

### Configuration:

### Suggestions and/or Issues:
Please use the issue tracker on github
