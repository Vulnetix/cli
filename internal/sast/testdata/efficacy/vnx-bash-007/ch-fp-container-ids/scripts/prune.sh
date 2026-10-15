#!/bin/bash
docker rm -f $(docker ps -aq)
docker rmi $(docker images -q --filter dangling=true)
podman stop $(podman ps -q)
