# FailStats
A very common tool to prevent brute force attacks on web facing services is [fail2ban](https://www.fail2ban.org/wiki/index.php/Main_Page), which bans IPs if they attempt to access a secured service and fail too many times. This project is an attempt to increase reporting of bans to the website [failstats.net](https://failstats.net).

This tool monitors the fail2ban log, reporting data to the [failstats.net](https://failstats.net) API. 

## Privacy Policy
This can be found in the footer of [failstats.net](https://failstats.net).

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
The configuration file can be found at ``/etc/failstats.conf``. Use any text editor such as nano or vim.

Configuration options:
- logDir: /var/log - The directory where the fail2ban logs can be found - shouldn't need changing
- logName: fail2ban - The name of the log files up to the first period i.e fail2ban = fail2ban.log
- repRateSeconds: 3600 - How frequently the log files are checked
- reportServices: 1 or 0 - 1 to report all service names, 0 to report "undisclosed" for all services
- dontReport: [] - A list of services to exclude from the service name reporting, e.g: ["jupyter", "nginx]

### Build instructions:
Fetch dependencies:
- ``go get github.com/gofrs/uuid``
- ``go get github.com/google/uuid``

Run tests:
- ``go fmt``
- ``go vet``
- ``go test -race``

Build:
- ``go build -o failstats``


### Suggestions and/or Issues:
Please use the issue tracker on github
