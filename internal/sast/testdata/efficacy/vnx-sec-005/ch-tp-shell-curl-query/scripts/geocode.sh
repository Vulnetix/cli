#!/bin/sh
~>curl -s "https://maps.googleapis.com/maps/api/geocode/json?address=$1&key=@@sample:AIza[0-9A-Za-z_-]{35}@@"
