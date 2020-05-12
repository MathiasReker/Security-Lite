<?php
/**
 * 2020 Mathias R.
 *
 * NOTICE OF LICENSE
 *
 * This file is licensed under the Software License Agreement
 * With the purchase or the installation of the software in your application
 * you accept the license agreement.
 *
 * @author    Mathias R.
 * @copyright Mathias R.
 * @license   Commercial license (You can not resell or redistribute this software.)
 */

include __DIR__ . '/../../config/config.inc.php';

include __DIR__ . '/../../init.php';

if (false === \mb_strpos(@\ini_get('disable_functions'), 'set_time_limit')) {
    @\set_time_limit(1200);
}
\ignore_user_abort(true);

if (!Tools::isPHPCLI()) {
    if (Tools::substr(Tools::encrypt('backupdb/cron'), 0, 32) !== Tools::getValue('token') || !Module::isInstalled('securitylite')) {
        die('Bad token');
    }
    echo 'Success';
}

$securitypro = Module::getInstanceByName('securitylite');

if ($securitypro->active) {
    $securitypro->cron = 1;
    $securitypro->backupDatabase();
}
