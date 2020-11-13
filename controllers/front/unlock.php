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

class SecurityLiteUnlockModuleFrontController extends ModuleFrontController
{
    /** @var bool */
    public $ajax;

    /**
     * Display content
     */
    public function display()
    {
        @\ignore_user_abort(true);

        if (true === (bool) Configuration::get('PRO_DEBUG_CRON')) {
            @\ini_set('display_errors', 1);
            @\ini_set('display_startup_errors', 1);
            @\error_reporting(\E_ALL);
        }

        $this->ajax = 1;

        // Check token
        if (!Tools::isPHPCLI()) {
            if ($this->module->encrypt('securitylite/unlock') !== Tools::getValue('token') || !Module::isInstalled('securitylite')) {
                $response = $this->module->l('Forbidden call.', 'unlock');
                $this->ajaxDie($response);
            }
        }

        // Try to run cronjob
        try {
            $response = $this->runCronjob();
        } catch (Exception $e) {
            if (true === (bool) Configuration::get('PRO_DEBUG_CRON')) {
                $response = $e;
            } else {
                $response = $this->module->l('Something went wrong.', 'unlock');
            }
        } finally {
            $this->ajaxDie($response);
        }
    }

    /**
     * Run cronjob
     *
     * @return string
     */
    private function runCronjob()
    {
        // Check if module is activated
        if (true === (bool) $this->module->active) {
            $this->module->cron = 1;
        } else {
            return $this->module->l('securitylite is not active.', 'unlock');
        }

        return $this->module->l('Success!', 'unlock');
    }
}
