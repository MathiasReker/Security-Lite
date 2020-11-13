<?php
/**
 * This file is part of the securitylite package.
 *
 * @author Mathias Reker
 * @copyright Mathias Reker
 * @license Commercial Software License
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

if (!\defined('_PS_VERSION_')) {
    exit;
}

/**
 * File: /upgrade/upgrade-5.0.0.php
 *
 * @param object $module
 */
function upgrade_module_5_0_0($module)
{
    $module->registerHook(
        [
            'displayBackOfficeTop',
            'displayHeader',
            'displayMaintenance',
        ]
    );

    if (Tools::version_compare(_PS_VERSION_, '1.7.7.0', '>=')) {
        $module->registerHook(
            [
                'actionAdminLoginControllerBefore',
            ]
        );
    }

    return true;
}
