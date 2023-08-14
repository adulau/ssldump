# Docker instructions

*Note: Dockerfiles are only provided for Debian-like distributions so far.*

## Configure image building:

Uncomment the distribution reference you want to use, in top section in
`debian-distros/Dockerfile`.

## Build the image:

`cd debian-distros`

`./docker_build.sh`

## Run the container, and start ssldump inside the container:

`./docker_run.sh`

`(in container) sudo ssldump -n -i eth0 -j -AH`

## Mirror traffic to container

Outside of the container, adjust local interface name and container IP address
in `mirror_traffic_to_container.sh`.

Then mirror local traffic to ssldump container:

`./mirror_traffic_to_container.sh`

