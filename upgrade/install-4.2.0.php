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

if (!\defined('_PS_VERSION_')) {
    exit;
}

function upgrade_module_4_2_0($module)
{
    $module->registerHook(
        [
            'displayAdminLogin',
            'actionBeforeSubmitAccount',
        ]
    );

    $sql = [];
    $sql[] = 'CREATE TABLE IF NOT EXISTS `' . _DB_PREFIX_ . 'securitylite_tfa` (
        `enabled` int(1) NOT NULL,
        `secret` varchar(32) NOT NULL
        ) ENGINE=' . _MYSQL_ENGINE_ . ' DEFAULT CHARSET=UTF8;
        ';

    foreach ($sql as $query) {
        if (false === Db::getInstance()->execute($query)) {
            return false;
        }

        return true;
    }
}
