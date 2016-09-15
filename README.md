# Honeycomb Nginx Installer

## How to run it

(replace 3 below with the most recent [travis build](https://travis-ci.org/honeycombio/nginx_installer) number.)

    wget -q -O nginx_installer https://honeycomb.io/download/nginx_installer/1.3 && \
    #echo "abcabc123123examplesha256checksum123123abcabc quickstart" | sha256sum -c && \
    chmod 755 ./nginx_installer && ./nginx_installer

## What it does

* Looks for your nginx configuration
* Looks for your log files
* Backfill existing log data into honeycomb to get you started in one minute.
* Reviews your log file configuration maybe suggests some helpful additions
* Gets you up and running with honeytail for nginx.
