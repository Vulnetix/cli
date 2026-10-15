<?php

function acme_orders_table()
{
    global $wpdb;
    return $wpdb->prefix . 'acme_orders';
}

function acme_orders_count()
{
    global $wpdb;
    return (int) $wpdb->get_var("SELECT COUNT(*) FROM " . acme_orders_table());
}

function acme_orders_for_post()
{
    global $wpdb, $post;
    return $wpdb->get_results($wpdb->prepare("SELECT * FROM " . acme_orders_table() . " WHERE post_id = %d", $post->ID));
}
