#!/bin/bash
su - deploy
sudo su -c 'systemctl restart app'
runuser -u app -- /srv/bin/migrate "$1"
summary -c "$1"
