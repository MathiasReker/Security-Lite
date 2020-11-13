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

class AdminSecurityLiteController extends ModuleAdminController
{
    public function __construct()
    {
        parent::__construct();

        return \Tools::redirectAdmin(\Context::getContext()->link->getAdminLink('AdminModules', true) . '&configure=securitylite&tab_reset=1');
    }
}
