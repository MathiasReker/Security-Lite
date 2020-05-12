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

class AdminSecurityLiteController extends ModuleAdminController
{
    public function __construct()
    {
        parent::__construct();

        \Tools::redirectAdmin(\Context::getContext()->link->getAdminLink('AdminModules', true) . '&configure=securitylite');
    }
}
