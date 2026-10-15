#!/bin/sh
useradd -m deploy
~>chage -M 720 deploy
~>passwd -x 400 backup
