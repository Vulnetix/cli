<?php
~>$conn = ldap_connect("ldap://@@sample:d[c]01[.]co[r]p[.][a]cm[e]co[r]p[.][l]oc[a]l@@");
ldap_set_option($conn, LDAP_OPT_PROTOCOL_VERSION, 3);
