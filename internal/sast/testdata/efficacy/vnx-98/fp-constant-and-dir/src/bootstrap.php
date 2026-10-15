<?php
require_once __DIR__ . '/vendor/autoload.php';
include 'config.php';
$plugin = $config['plugin'];
include $pluginDir . '/' . $plugin . '.php';
foreach (glob(__DIR__ . '/modules/*.php') as $module) {
    require_once $module;
}
$name = $_GET['name'];
echo "Hello " . htmlspecialchars($name);
