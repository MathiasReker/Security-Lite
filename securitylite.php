<?php
/**
 * 2019 Mathias R.
 *
 * NOTICE OF LICENSE
 *
 * This file is licensed under the Software License Agreement
 * With the purchase or the installation of the software in your application
 * you accept the license agreement
 *
 * @author    Mathias R.
 * @copyright Mathias R.
 * @license   Commercial license (You can not resell or redistribute this software.)
 */

if (!defined('_PS_VERSION_')) {
    die;
}

class SecurityLite extends Module
{
    public function __construct()
    {
        $this->name = 'securitylite';
        $this->tab = 'administration';
        $this->version = '2.0.0';
        $this->author = 'Mathias Reker';
        $this->module_key = '';
        $this->need_instance = 0;
        $this->bootstrap = 1;
        parent::__construct();
        $this->displayName = $this->l('Security Lite');
        $this->description = $this->l('This module increases the overall security of your PrestaShop website.');
        $this->ps_versions_compliancy = [
            'min' => '1.7',
            'max' => _PS_VERSION_,
        ];
    }

    public function install()
    {
        include _PS_MODULE_DIR_ . $this->name . '/sql/install.php';

        $this->checkHtaccess();

        Configuration::updateValue('LITE_BAN_TIME', 30);
        Configuration::updateValue('LITE_MAX_RETRY', 5);
        Configuration::updateValue('LITE_FIND_TIME', 10);

        $hook = [
            'displayHeader',
            'displayBackOfficeTop',
        ];

        return parent::install() && $this->registerHook($hook);
    }

    public function uninstall()
    {
        include _PS_MODULE_DIR_ . $this->name . '/sql/uninstall.php';

        $form_values = $this->getConfigFormValues();

        foreach (array_keys($form_values) as $key) {
            Configuration::deleteByName($key);
        }
        $file = _PS_ROOT_DIR_ . '/.htaccess';

        if (file_exists($file)) {
            $this->removeHtaccessContent($file);
        }

        return parent::uninstall();
    }

    public function getContent()
    {
        $out = null;

        $url = 'https://addons.prestashop.com/en/website-security-access/44413-security-pro.html';

        if (isset($_SERVER['HTACCESS'])) {
            $out .= $this->displayInformation($this->l('All features in') . ' <a href="' . $url . '" target="_blank">Security Pro</a> ' . $this->l('will work on your setup!') . ' (' .
                $_SERVER['SERVER_SOFTWARE'] . ')');
        } else {
            $out .= $this->displayInformation($this->l('Some features in') . ' <a href="' . $url . '" target="_blank">Security Pro</a> ' . $this->l('might not work on your setup, because your .htaccess file is not used!') . ' (' . $_SERVER['SERVER_SOFTWARE'] . ')');
        }

        if ((bool) Tools::isSubmit('submitSecurityLiteModule')) {
            $this->postProcess();

            $this->chmodFileDir(_PS_ROOT_DIR_);

            $out .= $this->displayConfirmation($this->l('Settings updated!'));

            if (Configuration::get('LITE_FAIL2BAN')) {
                if (!Validate::isInt(Configuration::get('LITE_BAN_TIME')) || Configuration::get('LITE_BAN_TIME') <= 0) {
                    $out .= $this->displayWarning($this->l('"Ban time" needs to be an integer and greater than 0.'));
                    Configuration::updateValue('LITE_FAIL2BAN', 0);
                }

                if (!Validate::isInt(Configuration::get('LITE_FIND_TIME'))
                    || Configuration::get('LITE_BAN_TIME') <= 0) {
                    $out .= $this->displayWarning('"Find time" needs to be an integer and greater than 0.');
                    Configuration::updateValue('LITE_FAIL2BAN', 0);
                }

                if (!Validate::isInt(Configuration::get('LITE_MAX_RETRY'))
                    || Configuration::get('LITE_BAN_TIME') <= 0) {
                    $out .= $this->displayWarning($this->l('"Max retry" needs to be an integer and greater than 0.'));
                    Configuration::updateValue('LITE_FAIL2BAN', 0);
                }
            }

            if (Configuration::get('LITE_PERMISSIONS')) {
                $out .= $this->displayConfirmation($this->l('Permissions updated!'));

                if (!empty($this->error_dir)) {
                    $out .= $this->displayWarning($this->error_dir);
                }

                if (!empty($this->error_file)) {
                    $out .= $this->displayWarning($this->error_file);
                }
                Configuration::updateValue('LITE_PERMISSIONS', 0);
            }
        }

        return $out . $this->renderForm() . $this->checkSystem() . $this->securityPro();
    }

    public function checkHtaccess()
    {
        $Prestashop_closing = '# ~~end~~ Do not remove this comment, Prestashop will keep automatically the code outside this comment when .htaccess will be generated again';
        $security_lite_starts = '# ~security_lite~';
        $current = 'SetEnv HTACCESS on';
        $security_lite_ends = '# ~security_lite_end~';

        if (!$htaccess_content = Tools::file_get_contents(_PS_ROOT_DIR_ . '/.htaccess')) {
            Tools::generateHtaccess();
            $htaccess_content = Tools::file_get_contents(_PS_ROOT_DIR_ . '/.htaccess');
        }
        $content_to_add = $security_lite_starts . PHP_EOL . $current . PHP_EOL . $security_lite_ends;

        if (preg_match('/\# ~security_lite~(.*?)\# ~security_lite_end~/s', $htaccess_content, $m)) {
            $content_to_remove = $m[0];
            $htaccess_content = str_replace($content_to_remove, $content_to_add, $htaccess_content);
        } else {
            $htaccess_content = str_replace($Prestashop_closing, $Prestashop_closing . PHP_EOL . PHP_EOL . $content_to_add, $htaccess_content);
        }
        file_put_contents(_PS_ROOT_DIR_ . '/.htaccess', $htaccess_content);
    }

    public function hookDisplayHeader($params)
    {
        $this->blockIp();

        if (Configuration::get('LITE_DISABLE_RIGHT_CLICK')) {
            $this->context->controller->addJS(
                $this->context->link->getBaseLink() .
                'modules/securitylite/views/js/contextmenu.js'
            );
        }
    }

    public function hookDisplayBackOfficeTop($params)
    {
        if (Configuration::get('LITE_FAIL2BAN')) {
            $email = Tools::getValue('email');
            $passwd = Tools::getValue('passwd');

            if (Tools::isSubmit('submitLogin') && $email && $passwd) {
                $banTime = Configuration::get('LITE_BAN_TIME') * 60;
                $employeeBanTime = $this->getBanTime($email);

                if (time() - $employeeBanTime <= $banTime) {
                    $this->ban();
                }
                $employee = new Employee();
                $isLoaded = $employee->getByEmail($email, $passwd);

                if (!$isLoaded) {
                    Db::getInstance()->insert('securitylite', [
                        'email' => $email,
                        'ip' => $_SERVER['REMOTE_ADDR'],
                    ]);
                }

                $findTime = ConfigurationCore::get('LITE_FIND_TIME') * 60;
                $eldestAccessTime = $this->getEldestAccessTry($email);

                if ($eldestAccessTime && time() - $eldestAccessTime <= $findTime) {
                    Db::getInstance()->insert('securitylite', [
                        'email' => $email,
                        'ip' => $_SERVER['REMOTE_ADDR'],
                        'banned' => 1,
                    ]);
                    $this->ban();
                }
            }
        }
    }

    public function securityPro()
    {
        if (Language::countActiveLanguages() > 1) {
            $shop_url = $this->context->link->getBaseLink() . '/' . $this->context->language->iso_code . '/';
        } else {
            $shop_url = $this->context->link->getBaseLink();
        }

        $ps_url = 'https://addons.prestashop.com/en/website-security-access/44413-security-pro.html';

        return '<div class="panel">
        <h3>Upgrade to Security Pro</h3>
        <p style="font-size:130%;">
            Improve security of your PrestaShop website: 
            Fix insecure file permissions, protect your back-end area, 
            increase font office security and much more with <strong>Security Pro</strong>!<br>
            With <strong>Security Pro</strong> the risk of getting hacked is decreased. 
            You should always care about security.<br>
            By using <strong>Security Pro</strong> module, you add another layer of security to your PrestaShop website, 
            that will benefit you in case someone tries to get unauthorized access.
            <br><br>
            <h1>Only <strong style="color: green;">59,99€ excl.</strong> Tax as an onetime fee! Free support!</h1>
            <a href="' . $ps_url . '" target="_blank">
            <button type="button" class="btn btn-primary btn-lg">Upgrade to Security Pro</button></a>
            <a href="' . $ps_url . '" target="_blank">
            <button type="button" class="btn btn-primary-outline btn-lg">Read more</button></a>
            <a href="https://addons.prestashop.com/en/contact-us?id_product=44413" target="_blank">
            <button type="button" class="btn btn-primary-outline btn-lg">Contact the developer</button></a>
        </p>
        <br>
        <a href="' . $ps_url . '" target="_blank">
        <img src="' . $this->context->link->getBaseLink() . 'modules/' .
        $this->name . '/views/img/security-pro.png"></a>
        <br><br><br>
            <p style="font-size:130%;"><strong>Security Pro</strong> will fix all warnings and errors reported by <strong>https://securityheaders.com</strong>; you will get <strong style="color: green;">A+</strong> score! Want to know your score at the moment? <a href="https://securityheaders.com/?q=' . $shop_url . '&hide=on&followRedirects=on" target="_blank">
            <button type="button" class="btn btn-primary btn-lg">Check security score</button></a></p><br>
            <h1>With Security Pro:</h1>
        <img src="' . $this->context->link->getBaseLink() . 'modules/' .
        $this->name . '/views/img/security-scan.png"></div>';
    }

    public function checkSystem()
    {
        $pro_feature = '<span style="color: #25beef;"><strong>' . $this->l('PRO FEATURE!') . '</strong></span>';
        $helper_list = new HelperList();
        $helper_list->module = $this;
        $helper_list->title = $this->l('Scans your system for known security vulnerabilities and recommends options for increased protection');
        $helper_list->shopLinkType = '';
        $helper_list->no_link = true;
        $helper_list->show_toolbar = true;
        $helper_list->simple_header = false;
        $helper_list->currentIndex = $this->context->link->getAdminLink('AdminModules', false) .
        '&configure=' . $this->name;
        $helper_list->token = Tools::getAdminTokenLite('AdminModules');
        $check = '<i class="icon icon-check" style="color: green"></i>';
        $vulnerable = '<i class="icon icon-times" style="color: red"></i>';
        $fields_list = [
            'check' => [
                'title' => '<strong>' . $this->l('Check') . '</strong>',
                'search' => false,
                'float' => true,
            ],
            'status' => [
                'title' => '<strong>' . $this->l('Status') . '</strong>',
                'search' => false,
                'float' => true,
            ],
            'fix' => [
                'title' => '<strong>' . $this->l('How to fix') . '</strong>',
                'search' => false,
                'float' => true,
            ],
        ];
        $result = [
            [
                'check' => '<a href="https://nvd.nist.gov/vuln/detail/CVE-2018-19355" target="_blank">' . $this->l('CVE-2018-19355') . '</a>',
                'status' => file_exists(_PS_MODULE_DIR_ . 'orderfiles/upload.php') ? $vulnerable : $check,
                'fix' => $this->l('Upgrade PrestaShop to latest version'),
            ],
            [
                'check' => '<a href="https://nvd.nist.gov/vuln/detail/CVE-2018-19124" target="_blank">CVE-2018-19124</a>, ' .
                '<a href="https://nvd.nist.gov/vuln/detail/CVE-2018-19125" target="_blank">CVE-2018-19125</a>, ' .
                '<a href="https://nvd.nist.gov/vuln/detail/CVE-2018-19126" target="_blank">CVE-2018-19126</a>',
                'status' => 1 == $this->checkCVE201819126() ? $vulnerable : $check,
                'fix' => $this->l('Set') . ' "phar.readonly = Off" ' . $this->l('in file') . ': ' . php_ini_loaded_file(),
            ],
            [
                'check' => '<a href="https://nvd.nist.gov/vuln/detail/CVE-2018-13784" target="_blank">CVE-2018-13784</a>',
                'status' => 1 == version_compare(_PS_VERSION_, '1.7.3.4', '<') ? $vulnerable : $check,
                'fix' => $this->l('Upgrade PrestaShop to latest version'),
            ],
            [
                'check' => '<a href="https://nvd.nist.gov/vuln/detail/CVE-2018-8823" target="_blank">CVE-2018-8823</a>, ' .
                '<a href="https://nvd.nist.gov/vuln/detail/CVE-2018-8824" target="_blank">CVE-2018-8824</a>',
                'status' => 1 == $this->checkCVE20188824() ? $vulnerable : $check,
                'fix' => $this->l('Upgrade module: Responsive Mega Menu (Horizontal+Vertical+Dropdown) Pro'),
            ],
            [
                'check' => '<a href="https://nvd.nist.gov/vuln/detail/CVE-2018-7491" target="_blank">CVE-2018-7491</a>',
                'status' => 1 == $this->checkCVE20187491() ? $vulnerable : $check,
                'fix' => $this->l('Enable "Click-jack protection" in "Secure FO" above'),
            ],
            [
                'check' => $this->l('PHP version') . ' (' . PHP_VERSION . ')',
                'status' => $pro_feature,
                'fix' => $pro_feature,
            ],
            [
                'check' => $this->l('PHP information leakage (version)'),
                'status' => $pro_feature,
                'fix' => $pro_feature,
            ],
            [
                'check' => $this->l('PHP information leakage (logs)'),
                'status' => $pro_feature,
                'fix' => $pro_feature,
            ],
            [
                'check' => $this->l('SSL enabled'),
                'status' => $pro_feature,
                'fix' => $pro_feature,
            ],
            [
                'check' => $this->l('SSL Enabled everywhere'),
                'status' => $pro_feature,
                'fix' => $pro_feature,
            ],
            [
                'check' => $this->l('PrestaShop token'),
                'status' => $pro_feature,
                'fix' => $pro_feature,
            ],
            [
                'check' => 'mod_security',
                'status' => $pro_feature,
                'fix' => $pro_feature,
            ],
            [
                'check' => 'phpinfo.php',
                'status' => $pro_feature,
                'fix' => $pro_feature,
            ],
            [
                'check' => 'phppsinfo.php',
                'status' => $pro_feature,
                'fix' => $pro_feature,
            ],
            [
                'check' => 'robots.txt',
                'status' => $pro_feature,
                'fix' => $pro_feature,
            ],
            [
                'check' => '.htaccess',
                'status' => $pro_feature,
                'fix' => $pro_feature,
            ],
            [
                'check' => 'PrestaShop admin directory name',
                'status' => $pro_feature,
                'fix' => $pro_feature,
            ],
            [
                'check' => $this->l('Database table prefix'),
                'status' => $pro_feature,
                'fix' => $pro_feature,
            ],
            [
                'check' => $this->l('PrestaShop debug mode'),
                'status' => $pro_feature,
                'fix' => $pro_feature,
            ],
        ];

        return $helper_list->generateList($result, $fields_list);
    }

    protected function renderForm()
    {
        $helper = new HelperForm();
        $helper->show_toolbar = 0;
        $helper->table = $this->table;
        $helper->module = $this;
        $helper->default_form_language = $this->context->language->id;
        $helper->allow_employee_form_lang = Configuration::get('PS_BO_ALLOW_EMPLOYEE_FORM_LANG', 0);
        $helper->identifier = $this->identifier;
        $helper->submit_action = 'submitSecurityLiteModule';
        $helper->currentIndex = $this->context->link->getAdminLink('AdminModules', 0) . '&configure=' . $this->name .
        '&tab_module=' . $this->tab . '&module_name=' . $this->name;
        $helper->token = Tools::getAdminTokenLite('AdminModules');
        $helper->tpl_vars = [
            'fields_value' => $this->getConfigFormValues(),
            'languages' => $this->context->controller->getLanguages(),
            'id_language' => $this->context->language->id,
        ];

        return $helper->generateForm([
            $this->fieldsForm(),
        ]);
    }

    protected function fieldsForm()
    {
        $pro_feature = '<span style="color: #25beef;"><strong>' . $this->l('PRO FEATURE!') . '</strong></span> ';

        return [
            'form' => [
                'legend' => [
                    'title' => $this->l('Security Lite Settings'),
                ],
                'description' => $this->l('You don\'t need to save before going to the next tab. You can save all tabs in one click.'),
                'tabs' => [
                    'protectBackOffice' => '<i class="icon-lock"></i> ' . $this->l('Protect BO'),
                    'secondLogin' => '<i class="icon icon-sign-in"></i> ' . $this->l('Second login'),
                    'secureFrontOffice' => '<i class="icon icon-shield"></i> ' . $this->l('Secure FO'),
                    'blockIps' => '<i class="icon icon-ban"></i> ' . $this->l('Block IP\'s'),
                    'permissions' => '<i class="icon icon-file-o"></i> ' . $this->l('Permissions'),
                    'index' => '<i class="icon icon-sitemap"></i> ' . $this->l(
                        'Index'
                    ),
                    'fileChanges' => '<i class="icon icon-files-o"></i> ' . $this->l(
                        'File changes'
                    ),
                    'malwareScan' => '<i class="icon icon-search"></i> ' . $this->l('Scan for malware'),
                    'protectContent' => '<i class="icon icon-hand-o-up"></i> ' . $this->l('Protect content'),
                    'adminFolder' => '<i class="icon icon-folder-o"></i> ' . $this->l('Admin directory'),
                ],
                'input' => [
                    [
                        'tab' => 'protectBackOffice',
                        'type' => 'switch',
                        'label' => $this->l('Activate brute force protection'),
                        'name' => 'LITE_FAIL2BAN',
                        'is_bool' => 1,
                        'desc' => $this->l('Protects BO login-form against brute force attacks.'),
                        'values' => [
                            [
                                'id' => 'active_on',
                                'value' => 1,
                                'label' => $this->l('Enabled'),
                            ],
                            [
                                'id' => 'active_off',
                                'value' => 0,
                                'label' => $this->l('Disabled'),
                            ],
                        ],
                    ],
                    [
                        'col' => 2,
                        'tab' => 'protectBackOffice',
                        'type' => 'text',
                        'desc' => $this->l('Time a host is banned. Enter time in minutes.'),
                        'name' => 'LITE_BAN_TIME',
                        'prefix' => '<i class="icon icon-clock-o"></i>',
                        'suffix' => $this->l('minutes'),
                        'label' => $this->l('Ban time'),
                        'hint' => $this->l('Must be an integer'),
                    ],
                    [
                        'col' => 2,
                        'tab' => 'protectBackOffice',
                        'type' => 'text',
                        'desc' => $this->l('A host is banned if it has generated "max retry" during the last "find time". Enter time in minutes.'),
                        'name' => 'LITE_FIND_TIME',
                        'prefix' => '<i class="icon icon-clock-o"></i>',
                        'suffix' => $this->l('minutes'),
                        'label' => $this->l('Find time'),
                        'hint' => $this->l('Must be an integer'),
                    ],
                    [
                        'col' => 2,
                        'tab' => 'protectBackOffice',
                        'type' => 'text',
                        'desc' => $this->l('Wrong answers before ban.'),
                        'name' => 'LITE_MAX_RETRY',
                        'prefix' => '<i class="icon icon-user-times"></i>',
                        'suffix' => $this->l('times'),
                        'label' => $this->l('Max retry'),
                        'hint' => $this->l('Must be an integer'),
                    ],
                    [
                        'tab' => 'protectBackOffice',
                        'type' => 'switch',
                        'label' => $this->l('Receive e-mail'),
                        'name' => 'LITE_SEND_MAIL',
                        'is_bool' => 1,
                        'desc' => $pro_feature . $this->l('Receive an e-mail in case someone writes a wrong password. This setting can only be on if the whole function is activated.'),
                        'disabled' => 1,
                        'values' => [
                            [
                                'id' => 'active_on',
                                'value' => 1,
                                'label' => $this->l('Enabled'),
                            ],
                            [
                                'id' => 'active_off',
                                'value' => 0,
                                'label' => $this->l('Disabled'),
                            ],
                        ],
                    ],
                    [
                        'col' => 5,
                        'tab' => 'protectBackOffice',
                        'type' => 'text',
                        'desc' => $pro_feature . $this->l('Enter the e-mail witch you would like to be notified at.'),
                        'disabled' => 1,
                        'name' => 'LITE_FAIL2BAN_EMAIL',
                        'prefix' => '<i class="icon icon-envelope"></i>',
                        'label' => $this->l('E-mail'),
                        'hint' => $this->l('Must be a valid e-mail address'),
                    ],
                    [
                        'tab' => 'protectBackOffice',
                        'type' => 'text',
                        'col' => 5,
                        'desc' => $pro_feature . $this->l('Here you can list your own IP\'s to avoid getting an e-mail if you write the password wrong. You can still get banned for a period of time if you fail to login according to your own rules above. Separate IP\'s by comma (\',\').'),
                        'disabled' => 1,
                        'name' => 'LITE_WHITELIST_IPS',
                        'label' => $this->l('White-list IP\'s'),
                        'hint' => $this->l('E.g.') . ' 192.168.1.1,192.168.1.2,192.168.1.3',
                    ],
                    [
                        'tab' => 'permissions',
                        'type' => 'switch',
                        'label' => $this->l('Fix insecure file- and directory permissions'),
                        'name' => 'LITE_PERMISSIONS',
                        'is_bool' => 1,
                        'desc' => $this->l('Change file permissions to 644 and directory permissions to 755. This is highly recommended!'),
                        'values' => [
                            [
                                'id' => 'active_on',
                                'value' => 1,
                                'label' => $this->l('Enabled'),
                            ],
                            [
                                'id' => 'active_off',
                                'value' => 0,
                                'label' => $this->l('Disabled'),
                            ],
                        ],
                    ],
                    [
                        'tab' => 'index',
                        'type' => 'switch',
                        'label' => $this->l('Add missing index.php files'),
                        'name' => 'LITE_INDEX',
                        'is_bool' => 1,
                        'desc' => $pro_feature . $this->l('Fix directory traversal (observing) security vulnerability. 
                            This function adds missing index.php files to theme- and 
                            module directories. This is highly recommended!'),
                        'disabled' => 1,
                        'values' => [
                            [
                                'id' => 'active_on',
                                'value' => 1,
                                'label' => $this->l('Enabled'),
                            ],
                            [
                                'id' => 'active_off',
                                'value' => 0,
                                'label' => $this->l('Disabled'),
                            ],
                        ],
                    ],
                    [
                        'tab' => 'secureFrontOffice',
                        'type' => 'switch',
                        'label' => $this->l('Click-jack protection'),
                        'name' => 'LITE_CLICK_JACKING',
                        'is_bool' => 1,
                        'desc' => $pro_feature . $this->l('Prevent browsers from framing your site. This will defend you against attacks like click-jacking.'),
                        'disabled' => 1,
                        'values' => [
                            [
                                'id' => 'active_on',
                                'value' => 1,
                                'label' => $this->l('Enabled'),
                            ],
                            [
                                'id' => 'active_off',
                                'value' => 0,
                                'label' => $this->l('Disabled'),
                            ],
                        ],
                    ],
                    [
                        'tab' => 'secureFrontOffice',
                        'type' => 'switch',
                        'label' => $this->l('XSS protection'),
                        'name' => 'LITE_X_XSS_PPROTECTION',
                        'is_bool' => 1,
                        'desc' => $pro_feature . $this->l('Sets the configuration for the cross-site scripting filters built into most browsers.'),
                        'disabled' => 1,
                        'values' => [
                            [
                                'id' => 'active_on',
                                'value' => 1,
                                'label' => $this->l('Enabled'),
                            ],
                            [
                                'id' => 'active_off',
                                'value' => 0,
                                'label' => $this->l('Disabled'),
                            ],
                        ],
                    ],
                    [
                        'tab' => 'secureFrontOffice',
                        'type' => 'switch',
                        'label' => $this->l('Disable content sniffing'),
                        'name' => 'LITE_X_CONTENT_TYPE_OPTIONS',
                        'is_bool' => 0,
                        'desc' => $pro_feature . $this->l('Stop browsers from trying to MIME-sniff the content type and forces it to stick with the declared content-type.'),
                        'disabled' => 1,
                        'values' => [
                            [
                                'id' => 'active_on',
                                'value' => 1,
                                'label' => $this->l('Enabled'),
                            ],
                            [
                                'id' => 'active_off',
                                'value' => 0,
                                'label' => $this->l('Disabled'),
                            ],
                        ],
                    ],
                    [
                        'tab' => 'secureFrontOffice',
                        'type' => 'switch',
                        'label' => $this->l('Force secure connection with HSTS'),
                        'name' => 'LITE_STRICT_TRANSPORT_SECURITY',
                        'is_bool' => 1,
                        'desc' => $pro_feature . $this->l('Strengthens your implementation of TLS by getting the User 
                            Agent to enforce the use of HTTPS.'),
                        'disabled' => 1,
                        'values' => [
                            [
                                'id' => 'active_on',
                                'value' => 1,
                                'label' => $this->l('Enabled'),
                            ],
                            [
                                'id' => 'active_off',
                                'value' => 0,
                                'label' => $this->l('Disabled'),
                            ],
                        ],
                    ],
                    [
                        'tab' => 'secureFrontOffice',
                        'type' => 'switch',
                        'label' => $this->l('Expect CT'),
                        'name' => 'LITE_EXPECT_CT',
                        'is_bool' => 1,
                        'desc' => $pro_feature . $this->l('Enforce your CT policy.'),
                        'disabled' => 1,
                        'values' => [
                            [
                                'id' => 'active_on',
                                'value' => 1,
                                'label' => $this->l('Enabled'),
                            ],
                            [
                                'id' => 'active_off',
                                'value' => 0,
                                'label' => $this->l('Disabled'),
                            ],
                        ],
                    ],
                    [
                        'tab' => 'secureFrontOffice',
                        'type' => 'switch',
                        'label' => $this->l('Referrer policy'),
                        'name' => 'LITE_REFFERER_POLICY',
                        'is_bool' => 1,
                        'desc' => $pro_feature . $this->l('The browser will only set the referrer header on requests to the same origin. If the destination is another origin then no referrer information will be sent.'),
                        'disabled' => 1,
                        'values' => [
                            [
                                'id' => 'active_on',
                                'value' => 1,
                                'label' => $this->l('Enabled'),
                            ],
                            [
                                'id' => 'active_off',
                                'value' => 0,
                                'label' => $this->l('Disabled'),
                            ],
                        ],
                    ],
                    [
                        'tab' => 'secureFrontOffice',
                        'type' => 'switch',
                        'label' => $this->l('Cookie secure flag'),
                        'name' => 'LITE_COOKIE_SECURE',
                        'is_bool' => 1,
                        'disabled' => 1,
                        'desc' => $pro_feature . $this->l('By setting the secure flag, the browser will prevent the transmission of a cookie over an unencrypted channel.'),
                        'values' => [
                            [
                                'id' => 'active_on',
                                'value' => 1,
                                'label' => $this->l('Enabled'),
                            ],
                            [
                                'id' => 'active_off',
                                'value' => 0,
                                'label' => $this->l('Disabled'),
                            ],
                        ],
                    ],
                    [
                        'tab' => 'secureFrontOffice',
                        'type' => 'switch',
                        'label' => $this->l('Cookie HttpOnly flag'),
                        'name' => 'LITE_COOKIE_HTTPONLY',
                        'is_bool' => 1,
                        'disabled' => 1,
                        'desc' => $pro_feature . $this->l('Using the HttpOnly flag when generating a cookie helps mitigate the risk of client-side script accessing the protected cookie.'),
                        'values' => [
                            [
                                'id' => 'active_on',
                                'value' => 1,
                                'label' => $this->l('Enabled'),
                            ],
                            [
                                'id' => 'active_off',
                                'value' => 0,
                                'label' => $this->l('Disabled'),
                            ],
                        ],
                    ],
                    [
                        'tab' => 'secureFrontOffice',
                        'type' => 'switch',
                        'label' => $this->l('Block specific files'),
                        'name' => 'LITE_BLOCK_FILE_EXTENSIONS',
                        'is_bool' => 1,
                        'desc' => $pro_feature . $this->l('Block executing, downloading and reading files with extensions: aspx, bash, bak, dll, exe, git, hg, ini, jsp, log, mdb, out, sql, svn, swp, tar, rar, rdf.'),
                        'disabled' => 1,
                        'values' => [
                            [
                                'id' => 'active_on',
                                'value' => 1,
                                'label' => $this->l('Enabled'),
                            ],
                            [
                                'id' => 'active_off',
                                'value' => 0,
                                'label' => $this->l('Disabled'),
                            ],
                        ],
                    ],
                    [
                        'tab' => 'blockIps',
                        'type' => 'switch',
                        'label' => $this->l('Block bad user-agents / bots'),
                        'name' => 'LITE_BLOCK_USER_AGENTS',
                        'is_bool' => 1,
                        'desc' => $pro_feature . $this->l('Blocks a list of known bad user-agents / bots.'),
                        'disabled' => 1,
                        'values' => [
                            [
                                'id' => 'active_on',
                                'value' => 1,
                                'label' => $this->l(
                                    'Enabled'
                                ),
                            ],
                            [
                                'id' => 'active_off',
                                'value' => 0,
                                'label' => $this->l('Disabled'),
                            ],
                        ],
                    ],
                    [
                        'tab' => 'secondLogin',
                        'type' => 'switch',
                        'label' => $this->l('Activate second login for your BO'),
                        'name' => 'LITE_HTPASSWD',
                        'is_bool' => 1,
                        'desc' => $pro_feature . $this->l('Protects your BO area with .htpasswd. This is highly recommended!'),
                        'disabled' => 1,
                        'values' => [
                            [
                                'id' => 'active_on',
                                'value' => 1,
                                'label' => $this->l('Enabled'),
                            ],
                            [
                                'id' => 'active_off',
                                'value' => 0,
                                'label' => $this->l('Disabled'),
                            ],
                        ],
                    ],
                    [
                        'col' => 5,
                        'tab' => 'secondLogin',
                        'type' => 'text',
                        'prefix' => '<i class="icon icon-user"></i>',
                        'desc' => $pro_feature . $this->l('You should use another username than you do for your regular BO login.'),
                        'name' => 'LITE_HTPASSWD_USER',
                        'disabled' => 1,
                        'label' => $this->l('Username'),
                        'hint' => $this->l('Invalid character') . ': ":"',
                    ],

                    [
                        'col' => 5,
                        'tab' => 'secondLogin',
                        'type' => 'text',
                        'prefix' => '<i class="icon icon-key"></i>',
                        'desc' => $pro_feature . $this->l('You should use another password than you do for your regular BO login.'),
                        'disabled' => 1,
                        'name' => 'LITE_HTPASSWD_PASS',
                        'label' => $this->l('Password'),
                        'hint' => $this->l('Invalid character') . ': ":"',
                    ],
                    [
                        'tab' => 'blockIps',
                        'type' => 'switch',
                        'col' => 5,
                        'label' => $this->l('Block custom list of IP\'s'),
                        'name' => 'LITE_BAN_IP_ACTIVATE',
                        'is_bool' => 1,
                        'desc' => $this->l('Block users with below IP\'s from your website.'),
                        'values' => [
                            [
                                'id' => 'active_on',
                                'value' => 1,
                                'label' => $this->l('Enabled'),
                            ],
                            [
                                'id' => 'active_off',
                                'value' => 0,
                                'label' => $this->l('Disabled'),
                            ],
                        ],
                    ],
                    [
                        'tab' => 'blockIps',
                        'type' => 'textarea',
                        'col' => 5,
                        'desc' => $this->l('List all IP\'s you want to block from your website. Separate IP\'s by comma (\',\').'),
                        'name' => 'LITE_BAN_IP',
                        'label' => $this->l('Custom list of IP\'s'),
                        'hint' => 'E.g. 192.168.1.1,192.168.1.2,192.168.1.3',
                    ],
                    [
                        'tab' => 'fileChanges',
                        'type' => 'switch',
                        'label' => $this->l('Get an e-mail notification if files have changed'),
                        'name' => 'LITE_FILE_CHANGES',
                        'is_bool' => 1,
                        'desc' => $pro_feature . $this->l('This function tracks every file change on your server and let you know by e-mail if something changes. Once this option is on, you will get a link you can set up as a cron job.'),
                        'disabled' => 1,
                        'values' => [
                            [
                                'id' => 'active_on',
                                'value' => 1,
                                'label' => $this->l('Enabled'),
                            ],
                            [
                                'id' => 'active_off',
                                'value' => 0,
                                'label' => $this->l('Disabled'),
                            ],
                        ],
                    ],
                    [
                        'tab' => 'fileChanges',
                        'type' => 'text',
                        'col' => 5,
                        'disabled' => 1,
                        'desc' => $pro_feature . $this->l('Whitelist dynamic files. Separate files by comma (\',\').'),
                        'name' => 'LITE_FILE_CHANGES_WHITELIST',
                        'label' => $this->l('Whitelist filter'),
                        'hint' => $this->l('E.g.') . ' file.json,file.xml',
                    ],
                    [
                        'col' => 5,
                        'tab' => 'fileChanges',
                        'type' => 'text',
                        'prefix' => '<i class="icon icon-envelope"></i>',
                        'desc' => $pro_feature . $this->l('Enter the e-mail witch you would like to be notified at.'),
                        'disabled' => 1,
                        'name' => 'LITE_FILE_CHANGES_EMAIL',
                        'label' => $this->l('E-mail'),
                        'hint' => $this->l('Need to be a valid email address'),
                    ],
                    [
                        'tab' => 'malwareScan',
                        'type' => 'switch',
                        'label' => $this->l('Get an e-mail notification if the any infected file was found'),
                        'name' => 'LITE_MALWARE_SCAN',
                        'is_bool' => 1,
                        'desc' => $pro_feature . $this->l('This function scans all your directories for malicious code. Once this option is on, you will get a link you can set up as a cron job.'),
                        'disabled' => 1,
                        'values' => [
                            [
                                'id' => 'active_on',
                                'value' => 1,
                                'label' => $this->l('Enabled'),
                            ],
                            [
                                'id' => 'active_off',
                                'value' => 0,
                                'label' => $this->l('Disabled'),
                            ],
                        ],
                    ],
                    [
                        'tab' => 'malwareScan',
                        'type' => 'text',
                        'col' => 5,
                        'disabled' => 1,
                        'desc' => $pro_feature . $this->l('Whitelist false positives, caused by custom modules etc. Separate files by comma (\',\').'),
                        'name' => 'LITE_WHITELIST_MALWARE',
                        'label' => $this->l('Whitelist filter'),
                        'hint' => $this->l('E.g.') . ' file.js,file.php',
                    ],
                    [
                        'col' => 5,
                        'tab' => 'malwareScan',
                        'type' => 'text',
                        'prefix' => '<i class="icon icon-envelope"></i>',
                        'desc' => $pro_feature . $this->l('Enter the e-mail witch you would like to be notified at.'),
                        'disabled' => 1,
                        'name' => 'LITE_MALWARE_SCAN_EMAIL',
                        'label' => $this->l('E-mail'),
                        'hint' => $this->l('Need to be a valid email address'),
                    ],
                    [
                        'tab' => 'adminFolder',
                        'type' => 'switch',
                        'label' => $this->l('Are you sure, you want to change name of admin directory?'),
                        'name' => 'LITE_ADMIN_FOLDER',
                        'is_bool' => 1,
                        'desc' => $pro_feature . $this->l('You will be redirected to the new URL once you click "save" if this is set to "yes".'),
                        'disabled' => 1,
                        'values' => [
                            [
                                'id' => 'active_on',
                                'value' => 1,
                                'label' => $this->l('Enabled'),
                            ],
                            [
                                'id' => 'active_off',
                                'value' => 0,
                                'label' => $this->l('Disabled'),
                            ],
                        ],
                    ],
                    [
                        'col' => 5,
                        'tab' => 'adminFolder',
                        'type' => 'text',
                        'prefix' => $this->context->link->getBaseLink(),
                        'desc' => $pro_feature . $this->l('Your admin directory name should include both letters and numbers. Make it hard to guess; don\'t use "admin123".'),
                        'disabled' => 1,
                        'name' => 'LITE_ADMIN_FOLDER_NAME',
                        'label' => $this->l('Directory name'),
                        'hint' => $this->l('Accepted character:') . ' "a-z A-Z 0-9 _ . -"',
                    ],
                    [
                        'tab' => 'protectContent',
                        'type' => 'switch',
                        'label' => $this->l('Disable right click'),
                        'name' => 'LITE_DISABLE_RIGHT_CLICK',
                        'is_bool' => 1,
                        'desc' => $this->l('Disable right click mouse event.'),
                        'values' => [
                            [
                                'id' => 'active_on',
                                'value' => 1,
                                'label' => $this->l('Enabled'),
                            ],
                            [
                                'id' => 'active_off',
                                'value' => 0,
                                'label' => $this->l('Disabled'),
                            ],
                        ],
                    ],
                    [
                        'tab' => 'protectContent',
                        'type' => 'switch',
                        'label' => $this->l('Disable drag and drop'),
                        'name' => 'LITE_DISABLE_DRAG',
                        'disabled' => 1,
                        'is_bool' => 1,
                        'desc' => $pro_feature . $this->l('Disable drag and drop mouse event.'),
                        'values' => [
                            [
                                'id' => 'active_on',
                                'value' => 1,
                                'label' => $this->l('Enabled'),
                            ],
                            [
                                'id' => 'active_off',
                                'value' => 0,
                                'label' => $this->l('Disabled'),
                            ],
                        ],
                    ],
                    [
                        'tab' => 'protectContent',
                        'type' => 'switch',
                        'label' => $this->l('Disable copy'),
                        'name' => 'LITE_DISABLE_COPY',
                        'disabled' => 1,
                        'is_bool' => 1,
                        'desc' => $pro_feature . $this->l('Disable copy (E.g. Ctrl + C / Command + C).'),
                        'values' => [
                            [
                                'id' => 'active_on',
                                'value' => 1,
                                'label' => $this->l('Enabled'),
                            ],
                            [
                                'id' => 'active_off',
                                'value' => 0,
                                'label' => $this->l('Disabled'),
                            ],
                        ],
                    ],
                    [
                        'tab' => 'protectContent',
                        'type' => 'switch',
                        'label' => $this->l('Disable cut'),
                        'name' => 'LITE_DISABLE_CUT',
                        'disabled' => 1,
                        'is_bool' => 1,
                        'desc' => $pro_feature . $this->l('Disable cut (E.g. Ctrl + X / Command + X).'),
                        'values' => [
                            [
                                'id' => 'active_on',
                                'value' => 1,
                                'label' => $this->l('Enabled'),
                            ],
                            [
                                'id' => 'active_off',
                                'value' => 0,
                                'label' => $this->l('Disabled'),
                            ],
                        ],
                    ],
                    [
                        'tab' => 'protectContent',
                        'type' => 'switch',
                        'label' => $this->l('Disable paste'),
                        'name' => 'LITE_DISABLE_PASTE',
                        'is_bool' => 1,
                        'disabled' => 1,
                        'desc' => $pro_feature . $this->l('Disable paste (E.g. Ctrl + V / Command + V).'),
                        'values' => [
                            [
                                'id' => 'active_on',
                                'value' => 1,
                                'label' => $this->l('Enabled'),
                            ],
                            [
                                'id' => 'active_off',
                                'value' => 0,
                                'label' => $this->l('Disabled'),
                            ],
                        ],
                    ],
                    [
                        'tab' => 'protectContent',
                        'type' => 'switch',
                        'label' => $this->l('Disable text selection'),
                        'name' => 'LITE_DISABLE_TEXT_SELECTION',
                        'disabled' => 1,
                        'is_bool' => 1,
                        'desc' => $pro_feature . $this->l('Disable text selection.'),
                        'values' => [
                            [
                                'id' => 'active_on',
                                'value' => 1,
                                'label' => $this->l('Enabled'),
                            ],
                            [
                                'id' => 'active_off',
                                'value' => 0,
                                'label' => $this->l('Disabled'),
                            ],
                        ],
                    ],
                ],
                'submit' => [
                    'title' => $this->l('Save'),
                ],
            ],
        ];
    }

    protected function getConfigFormValues()
    {
        return [
            'LITE_CLICK_JACKING' => Configuration::get('LITE_CLICK_JACKING'),
            'LITE_X_XSS_PPROTECTION' => Configuration::get('LITE_X_XSS_PPROTECTION'),
            'LITE_X_CONTENT_TYPE_OPTIONS' => Configuration::get('LITE_X_CONTENT_TYPE_OPTIONS'),
            'LITE_STRICT_TRANSPORT_SECURITY' => Configuration::get('LITE_STRICT_TRANSPORT_SECURITY'),
            'LITE_EXPECT_CT' => Configuration::get('LITE_EXPECT_CT'),
            'LITE_REFFERER_POLICY' => Configuration::get('LITE_REFFERER_POLICY'),
            'LITE_COOKIE_SECURE' => Configuration::get('LITE_COOKIE_SECURE'),
            'LITE_COOKIE_HTTPONLY' => Configuration::get('LITE_COOKIE_HTTPONLY'),
            'LITE_BLOCK_FILE_EXTENSIONS' => Configuration::get('LITE_BLOCK_FILE_EXTENSIONS'),
            'LITE_BLOCK_USER_AGENTS' => Configuration::get('LITE_BLOCK_USER_AGENTS'),
            'LITE_HTPASSWD' => Configuration::get('LITE_HTPASSWD'),
            'LITE_HTPASSWD_USER' => Configuration::get('LITE_HTPASSWD_USER'),
            'LITE_HTPASSWD_PASS' => Configuration::get('LITE_HTPASSWD_PASS'),
            'LITE_PERMISSIONS' => Configuration::get('LITE_PERMISSIONS'),
            'LITE_INDEX' => Configuration::get('LITE_INDEX'),
            'LITE_BAN_IP' => Configuration::get('LITE_BAN_IP'),
            'LITE_BAN_IP_ACTIVATE' => Configuration::get('LITE_BAN_IP_ACTIVATE'),
            'LITE_FAIL2BAN' => Configuration::get('LITE_FAIL2BAN'),
            'LITE_FAIL2BAN_EMAIL' => Configuration::get('LITE_FAIL2BAN_EMAIL'),
            'LITE_BAN_TIME' => Configuration::get('LITE_BAN_TIME'),
            'LITE_MAX_RETRY' => Configuration::get('LITE_MAX_RETRY'),
            'LITE_FIND_TIME' => Configuration::get('LITE_FIND_TIME'),
            'LITE_SEND_MAIL' => Configuration::get('LITE_SEND_MAIL'),
            'LITE_WHITELIST_IPS' => Configuration::get('LITE_WHITELIST_IPS'),
            'LITE_FILE_CHANGES' => Configuration::get('LITE_FILE_CHANGES'),
            'LITE_FILE_CHANGES_WHITELIST' => Configuration::get('LITE_FILE_CHANGES_WHITELIST'),
            'LITE_FILE_CHANGES_EMAIL' => Configuration::get('LITE_FILE_CHANGES_EMAIL'),
            'LITE_MALWARE_SCAN' => Configuration::get('LITE_MALWARE_SCAN'),
            'LITE_WHITELIST_MALWARE' => Configuration::get('LITE_WHITELIST_MALWARE'),
            'LITE_MALWARE_SCAN_EMAIL' => Configuration::get('LITE_MALWARE_SCAN_EMAIL'),
            'LITE_DISABLE_RIGHT_CLICK' => Configuration::get('LITE_DISABLE_RIGHT_CLICK'),
            'LITE_DISABLE_COPY' => Configuration::get('LITE_DISABLE_COPY'),
            'LITE_DISABLE_CUT' => Configuration::get('LITE_DISABLE_CUT'),
            'LITE_DISABLE_PASTE' => Configuration::get('LITE_DISABLE_PASTE'),
            'LITE_DISABLE_DRAG' => Configuration::get('LITE_DISABLE_DRAG'),
            'LITE_DISABLE_TEXT_SELECTION' => Configuration::get('LITE_DISABLE_TEXT_SELECTION'),
            'LITE_ADMIN_FOLDER' => Configuration::get('LITE_ADMIN_FOLDER'),
            'LITE_ADMIN_FOLDER_NAME' => Configuration::get('LITE_ADMIN_FOLDER_NAME'),
        ];
    }

    protected function postProcess()
    {
        $form_values = $this->getConfigFormValues();

        foreach (array_keys($form_values) as $key) {
            Configuration::updateValue($key, Tools::getValue($key));
        }
    }

    private function removeHtaccessContent($path)
    {
        $htaccess_content = Tools::file_get_contents($path);

        if (preg_match('/\# ~security_lite~(.*?)\# ~security_lite_end~/s', $htaccess_content, $m)) {
            $content_to_remove = $m[0];
            $htaccess_content = str_replace($content_to_remove, '', $htaccess_content);
        }
        file_put_contents($path, $htaccess_content);
    }

    private function chmodFileDir($dir)
    {
        if (Configuration::get('LITE_PERMISSIONS')) {
            $perms = [];
            $perms['file'] = 0644;
            $perms['directory'] = 0755;
            $error_dir = null;
            $error_file = null;
            $dh = @opendir($dir);

            if ($dh) {
                while (false !== ($file = readdir($dh))) {
                    if ('.' !== $file && '..' !== $file) {
                        $fullpath = $dir . '/' . $file;

                        if (!is_dir($fullpath)) {
                            if (!chmod($fullpath, $perms['file'])) {
                                $error_file .= '<strong>' . $this->l('Failed') . '</strong> ' . $this->l('to set file permissions on') . ' ' . $fullpath . PHP_EOL;
                            }
                        } else {
                            if (chmod($fullpath, $perms['directory'])) {
                                $this->chmodFileDir($fullpath);
                            } else {
                                $error_dir .= '<strong>' . $this->l('Failed') . '</strong> ' . $this->l('to set directory permissions on') . ' ' . $fullpath . PHP_EOL;
                            }
                        }
                    }
                }
                closedir($dh);
            }
        }
    }

    private function blockIp()
    {
        if (Configuration::get('LITE_BAN_IP_ACTIVATE') && '' !== Configuration::get('LITE_BAN_IP')) {
            $deny = explode(',', preg_replace('/\s+/', '', Configuration::get('LITE_BAN_IP')));

            if (in_array($_SERVER['REMOTE_ADDR'], $deny)) {
                header('HTTP/1.1 403 Forbidden');

                die;
            }
        }
    }

    private function ban()
    {
        $this->context->employee->logout();

        die('Banned');
    }

    private function getBanTime($email)
    {
        $sql = new DbQuery();
        $sql->select('MAX(access_time) AS access_time');
        $sql->from('securitylite');
        $sql->where('banned = 1');
        $sql->where(sprintf('email = "%s"', pSQL($email)));
        $sqlResult = Db::getInstance()->executeS($sql);

        return $sqlResult ? strtotime($sql) : 0;
    }

    private function getEldestAccessTry($email)
    {
        $maxRetry = (int) ConfigurationCore::get('LITE_MAX_RETRY');
        $email = pSQL($email);
        $query = 'SELECT IF(COUNT(*) = ' . $maxRetry .
        ', MIN(access_time), \'0000-00-00 00:00:00\') AS access_time FROM (SELECT access_time FROM ' .
        _DB_PREFIX_ . 'securitylite WHERE banned = 0 AND email = "' .
        $email . '" ORDER BY access_time DESC LIMIT ' . $maxRetry . ') tmp';
        $accessStats = Db::getInstance()->getRow($query);

        return $accessStats ? strtotime($accessStats['access_time']) : 0;
    }

    private function checkCVE20187491()
    {
        if (Language::countActiveLanguages() > 1) {
            $url = $this->context->link->getBaseLink() . '/' . $this->context->language->iso_code . '/';
        } else {
            $url = $this->context->link->getBaseLink();
        }

        $headers = @get_headers($url, 1);

        if ('sameorigin' === is_array(Tools::strtolower(!empty($headers['X-Frame-Options']) ? $headers['X-Frame-Options'] : ''))
            || 'sameorigin' === Tools::strtolower(!empty($headers['X-Frame-Options']) ? $headers['X-Frame-Options'] : '')) {
            return 0;
        } else {
            return 1;
        }
    }

    private function checkCVE201819126()
    {
        if (version_compare(_PS_VERSION_, '1.7.4.4', '<')) {
            if (extension_loaded('phar') &&
                0 == ini_get('phar.readonly')) {
                return 1;
            } else {
                return 0;
            }
        }
    }

    private function checkCVE20188824()
    {
        if (file_exists(_PS_MODULE_DIR_ . 'bamegamenu/ajax_phpcode.php')) {
            $moduleVersion = Module::getInstanceByName('bamegamenu')->version;

            if (null !== $moduleVersion) {
                if (version_compare($moduleVersion, '1.0.32', '<=')) {
                    return 1;
                } else {
                    return 0;
                }
            }
        }
    }
}
