<?php

function legacy_boot()
{
~>    global $wpdb, $acme_settings, $acme_cache, $acme_user;
    $acme_settings = get_option('acme');
}
