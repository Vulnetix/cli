<?php
function show_posts() {
    global $wpdb;
    return $wpdb->get_results("SELECT 1");
}

function show_title() {
    global $post;
    return $post->post_title;
}

function show_query() {
    global $wp_query;
    return $wp_query->found_posts;
}

function read_state() {
    return $GLOBALS['state'];
}
