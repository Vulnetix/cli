<?php
$step = (int) ($_GET['step'] ?? 1);
include __DIR__ . '/steps/step' . $step . '.php';

$tab = match ($_GET['tab'] ?? '') {
    'billing' => 'tabs/billing.php',
    'team'    => 'tabs/team.php',
    default   => 'tabs/profile.php',
};
include $tab;
