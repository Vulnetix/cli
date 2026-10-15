package com.acme

fun telnetUrl(host: String): String = "telnet://" + host + ":23"
val ldapBase = "ldap://$ldapHost:389"
val redisUrl = "redis://${System.getenv("REDIS_HOST")}:6379"
