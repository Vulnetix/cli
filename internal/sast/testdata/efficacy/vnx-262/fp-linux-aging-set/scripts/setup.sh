#!/bin/sh
chage -M 90 -W 7 deploy
chage -E -1 deploy
passwd -x 60 deploy
