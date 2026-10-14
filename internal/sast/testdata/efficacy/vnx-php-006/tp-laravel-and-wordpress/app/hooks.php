<?php
function restore_widget($request) {
    $blob = $request->input("widget");
~>    return unserialize($blob);
}

function plugin_import() {
~>    $settings = maybe_unserialize( stripslashes( $_POST["settings"] ) );
    update_option("plugin_settings", $settings);
}
