<?php
function acme_export() {
    if (!current_user_can('manage_options')) {
~>        wp_redirect(admin_url());
    }
    acme_send_csv(get_all_orders());
}
