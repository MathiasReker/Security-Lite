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

$autoloadPath = _PS_MODULE_DIR_ . 'securitylite/vendor/autoload.php';
if (\file_exists($autoloadPath)) {
    require_once $autoloadPath;
}

class SecurityLite extends Module
{
    public $cron = 0;
    private $userIp;
    private $controlDb;
    private $controlLockDir;
    private $controlLockFile;
    private $scriptTmpDir;
    private $errorDir;
    private $errorFile;

    /**
     * Construct module.
     */
    public function __construct()
    {
        $this->name = 'securitylite';
        $this->tab = 'administration';
        $this->version = '4.5.1';
        $this->author = 'Mathias Reker';
        $this->module_key = '71a0dda36237f958642fb61a15ccc695';
        $this->need_instance = 0;
        $this->ps_versions_compliancy = [
            'min' => '1.6.1',
            'max' => _PS_VERSION_,
        ];
        $this->bootstrap = true;

        parent::__construct();

        $this->displayName = $this->l('Security Lite');
        $this->description = $this->l('This module increases the overall security of your PrestaShop website.');

        $this->confirmUninstall = $this->l('Are you sure you want to uninstall?');
        $this->proFeature = '<span style="color:#ff6600; font-weight:bold;">' . $this->l('PRO FEATURE') . '</span> ';
    }

    /**
     * Install module, database table and set default values.
     */
    public function install()
    {
        $this->installTab();
        if (Shop::isFeatureActive()) {
            Shop::setContext(Shop::CONTEXT_ALL);
        }

        include _PS_MODULE_DIR_ . 'securitylite/sql/install.php';

        Configuration::updateValue('LITE_BAN_TIME', 30);
        Configuration::updateValue('LITE_MAX_RETRY', 5);
        Configuration::updateValue('LITE_FIND_TIME', 10);
        Configuration::updateValue('LITE_ADMIN_DIRECTORY_NAME', \basename(_PS_ADMIN_DIR_));
        Configuration::updateValue('LITE_ANTI_MAX_REQUESTS', 50);
        Configuration::updateValue('LITE_ANTI_REQ_TIMEOUT', 5);
        Configuration::updateValue('LITE_ANTI_BAN_TIME', 600);
        Configuration::updateValue('LITE_BACKUP_DB_SAVED', 7);
        Configuration::updateValue('LITE_BACKUP_FILE_SAVED', 1);
        Configuration::updateValue('LITE_BLOCK_FILE_UPLOAD_BACK_OFFICE', 'exe,com,bat,vb,vbs,wsf,pif,php');

        $hooks = [
            'displayBackOfficeTop',
            'displayHeader',
        ];

        if (!parent::install() || !$this->registerHook($hooks)) {
            return false;
        }

        return true;
    }

    /**
     * Uninstall the module, reverse any changes and delete database table.
     */
    public function uninstall()
    {
        $this->uninstallTab();
        include _PS_MODULE_DIR_ . 'securitylite/sql/uninstall.php';

        foreach (\array_keys($this->getConfigFormValues()) as $key) {
            Configuration::deleteByName($key);
        }

        return parent::uninstall();
    }

    /**
     * Get secret TwoFactorAuth.
     *
     * @return string
     */
    public function getSecret()
    {
        $tfa = new RobThree\Auth\TwoFactorAuth(Configuration::get('PS_SHOP_NAME'), 6, 30, 'sha1');
        if (empty($this->getTwoFactorAuthDB('secret'))) {
            Db::getInstance()->insert('securitylite_tfa', [
                'enabled' => '0',
                'secret' => '',
            ]);
            $this->updateTwoFactorAuthDB('secret', $tfa->createSecret(160, true));
        }

        return $this->getTwoFactorAuthDB('secret');
    }

    /**
     * Run scripts depending on configuration. Display warnings and confirmations.
     *
     * @return array
     */
    public function getContent()
    {
        $cron = [];
        $out = "<script>    
    function add_field() {
        $(function() {
            var pass = secureRandomPassword.randomString({
                length: 24
            });
            var text = $('#LITE_PASSWORD_GENERATOR');
            text.val(pass);
        });
    }
    $(document).ready(function() {
        document.getElementById('LITE_HSTS_SETTINGS_0').disabled = true;
        document.getElementById('LITE_HSTS_SETTINGS_1').disabled = true;
    })
</script>";

        // Validate input: permissions
        if (true === (bool) Tools::isSubmit('btnPermissions')) {
            $this->chmodFileDirectory(_PS_ROOT_DIR_); // Change permissions

            $out .= $this->displayConfirmation($this->l('Permissions updated!'));

            if (!empty($this->error_dir)) {
                $out .= $this->displayWarning($this->error_dir);
            }

            if (!empty($this->error_file)) {
                $out .= $this->displayWarning($this->error_file);
            }
        }

        // Download translations
        if (true === (bool) Tools::isSubmit('transDownload')) {
            $this->exportTranslation();
        }

        // Submit save
        if (true === (bool) Tools::isSubmit('submitSecurityLiteModule')) {
            $this->postProcess();

            $out .= $this->displayConfirmation($this->l('Settings updated!'));

            // Validate Fail2ban
            if (true === (bool) Configuration::get('LITE_FAIL2BAN')) {
                if (!(int) Configuration::get('LITE_BAN_TIME') > 0) {
                    $out .= $this->displayWarning('"' . $this->l('Ban time') . '"' . $this->l('must be greater than 0.'));
                    Configuration::updateValue('LITE_FAIL2BAN', false);
                }

                if (!(int) Configuration::get('LITE_FIND_TIME') > 0) {
                    $out .= $this->displayWarning('"' . $this->l('Request timeout') . '"' . $this->l('must be greater than 0.'));
                    Configuration::updateValue('LITE_FAIL2BAN', false);
                }

                if (!(int) Configuration::get('LITE_MAX_RETRY') > 0) {
                    $out .= $this->displayWarning('"' . $this->l('Max retry') . '"' . $this->l('must be greater than 0.'));
                    Configuration::updateValue('LITE_FAIL2BAN', false);
                }
            }
        }

        // Validate IP activated setting
        if (Tools::isEmpty(Configuration::get('LITE_BAN_IP')) && false === Configuration::get('LITE_BAN_IP')) {
            Configuration::updateValue('LITE_BAN_IP_ACTIVATE', false);
        }

        // Validate UA activated setting
        if (false === (bool) Configuration::get('LITE_BLOCK_USER_AGENT')) {
            Configuration::updateValue('LITE_BLOCK_USER_AGENT_ACTIVATE', false);
        }

        // Validate file upload activated setting
        if (false === (bool) Configuration::get('LITE_BLOCK_FILE_UPLOAD_BACK_OFFICE')) {
            Configuration::updateValue('LITE_BLOCK_FILE_UPLOAD_BACK_OFFICE_ACTIVATE', false);
        }

        // Validate IP addresses
        $fieldIps = [
            'LITE_BAN_IP',
            'LITE_WHITELIST_PROTECT_CONTENT',
        ];

        foreach ($fieldIps as $fieldIp) {
            $this->validateIps($fieldIp);
        }

        // Validate user agents and whitelists
        $fieldStrings = [
            'LITE_BLOCK_USER_AGENT',
        ];

        foreach ($fieldStrings as $fieldString) {
            $this->validateCommaSeperatedString($fieldString);
        }

        // Files that should be deleted
        $files = [
            '0x666.php',
            '1.rar',
            '1.sql',
            '1.tar',
            '1.tar.gz',
            '1.tgz',
            '1.zip',
            'anonsha1a0.php',
            'backup.bz2',
            'backup.gz',
            'backup.rar',
            'backup.sql',
            'backup.sql.zip',
            'backup.tar',
            'backup.tar.gz',
            'backup.tgz',
            'backup.zip',
            'backup/backup.bz2',
            'backup/backup.gz',
            'backup/backup.rar',
            'backup/backup.tar',
            'backup/backup.tar.gz',
            'backup/backup.tgz',
            'backup/backup.zip',
            'bak.sql',
            'data.sql',
            'database.sql',
            'db_backup.sql',
            'db_backup.sql.gz',
            'docs/CHANGELOG.txt',
            'docs/readme_de.txt',
            'docs/readme_en.txt',
            'docs/readme_es.txt',
            'docs/readme_fr.txt',
            'docs/readme_it.txt',
            'dump.rar',
            'dump.sql',
            'dump.sql.gz',
            'dump.sql.tgz',
            'dump.tar',
            'dump.tar.gz',
            'dump.tgz',
            'dump.zip',
            'efi.php',
            'example.7z',
            'example.gz',
            'example.rar',
            'example.sql',
            'example.sql.gz',
            'example.tar',
            'example.tar.gz',
            'example.tgz',
            'example.zip',
            'f.php',
            'home.rar',
            'home.tar',
            'home.tar.gz',
            'home.tgz',
            'home.zip',
            'htdocs.tar',
            'htdocs.tar.gz',
            'htdocs.zip',
            'htodcs.rar',
            'info.php',
            'localhost.sql',
            'phpinfo.php',
            'phppsinfo.php',
            'public_html.rar',
            'public_html.tar',
            'public_html.tar.gz',
            'public_html.tgz',
            'public_html.zip',
            'README.md',
            'site.rar',
            'site.tar',
            'site.tar.gz',
            'site.tgz',
            'site.zip',
            'sql.sql',
            'sql.txt',
            'upload.rar',
            'upload.zip',
            'web.rar',
            'web.tar',
            'web.tar.gz',
            'web.zip',
            'www.7z',
            'www.gz',
            'www.rar',
            'www.sql',
            'www.sql.gz',
            'www.tar',
            'www.tar.bz2',
            'www.tar.gz',
            'www.tgz',
            'www.zip',
            'XsamXadoo_Bot.php',
            'XsamXadoo_Bot_All.php',
            'XsamXadoo_deface.php',
            'Xsam_Xadoo.html',
            'zjsjuddzjw.php',
            '_db_.sql',
            '_DB_.sql.zip',
            '_DB_.tar.gz',
        ];

        $checkedFiles = [];

        foreach ($files as $file) {
            $dir = _PS_ROOT_DIR_ . \DIRECTORY_SEPARATOR . $file;
            if (\file_exists($dir)) {
                $checkedFiles[] = $dir;
            }
        }

        $elements = \array_merge($checkedFiles, $this->checkFilesCVE20179841());

        if (!empty($elements)) {
            $show = true;
        } else {
            $show = false;
        }

        // Btn files
        if ((bool) Tools::isSubmit('btnFiles')) {
            if (!empty($elements)) {
                foreach ($this->checkFilesCVE20179841() as $checkedDir) {
                    if (\is_dir($checkedDir)) {
                        Tools::deleteDirectory($checkedDir);
                    }
                }
                foreach ($checkedFiles as $checkedFile) {
                    Tools::deleteFile($checkedFile);
                }
                $show = false;
                $out .= $this->displayConfirmation($this->l('Files successfully removed!'));
            }
        }

        if ('localhost' === $_SERVER['HTTP_HOST']) {
            $hostName = 'https://google.com';
        } else {
            $hostName = $this->getBaseURL();
        }
        $orignalParse = \parse_url($hostName, \PHP_URL_HOST);
        $get = \stream_context_create(
            [
                'ssl' => [
                    'capture_peer_cert' => true,
                ],
            ]
        );
        $read = \stream_socket_client(
            'ssl://' . $orignalParse . ':443',
            $errno,
            $errstr,
            30,
            \STREAM_CLIENT_CONNECT,
            $get
        );
        $cert = \stream_context_get_params($read);
        $certInfo = \openssl_x509_parse(
            $cert['options']['ssl']['peer_certificate']
        );

        switch ($certInfo['version']) {
            case 1:
                $tlsVersion = 'TLS 1.1';
                break;
            case 2:
                $tlsVersion = 'TLS 1.2';
                break;
            case 3:
                $tlsVersion = 'TLS 1.3';
                break;

            default:
                $tlsVersion = $this->l('Unknown');
        }

        $lang = $this->context->language->iso_code;

        switch ($lang) {
            case 'fr':
                $trans = 'fr/contactez-nous';
                break;
            case 'es':
                $trans = 'es/contacte-con-nosotros';
                break;
            case 'de':
                $trans = 'de/contact-us';
                break;
            case 'it':
                $trans = 'it/contact-us';
                break;
            case 'nl':
                $trans = 'nl/contact-us';
                break;
            case 'pl':
                $trans = 'pl/contact-us';
                break;
            case 'pt':
                $trans = 'pt/contact-us';
                break;
            case 'ru':
                $trans = 'ru/contact-us';
                break;

            default:
                $trans = 'en/contact-us';
        }

        $contactUrl = 'https://addons.prestashop.com/' . $trans . '?id_product=44413';

        // Assign variables to smarty
        $this->context->smarty->assign([
            'currentUrl' => $this->context->link->getAdminLink('AdminModules', true) . '&configure=securitylite',
            'shopUrl' => $hostName,
            'elements' => $elements,
            'show' => $show,
            'getVarified' => $certInfo['issuer']['O'],
            'sslEnabled' => (bool) Configuration::get('PS_SSL_ENABLED'),
            'getIssuer' => $certInfo['issuer']['CN'],
            'expirationDate' => \date('Y-m-d', ($certInfo['validTo_time_t'])),
            'diffInDays' => \round(($certInfo['validTo_time_t'] - \time()) / (86400)),
            'getSignatureAlgorithm' => $certInfo['signatureTypeSN'],
            'getTlsVersion' => $tlsVersion,
            'mixedContentScannerUrl' => '#',
            'contactUrl' => $contactUrl,
        ]);

        // Validate input: Database backup
        if (true === (bool) Configuration::get('LITE_BACKUP_DB') || true === (bool) Configuration::get('LITE_BACKUP_DB_DROPBOX')) {
            $linkBackupDbCron = $this->getBaseURL() . 'modules/securitylite/backupdb-cron.php?token=' . \Tools::substr(\Tools::encrypt('backupdb/cron'), 0, 32);
            $cron[] = $this->l('Database backup') . '. ' . $this->l('URL') . ': <strong><a href="' . $linkBackupDbCron . '" target="_blank" rel="noopener noreferrer">' . $linkBackupDbCron . '</a></strong>';
        }

        // Empty password
        Configuration::updateValue('LITE_PASSWORD_GENERATOR', null);

        if (!empty($cron)) {
            $text = '<strong>' . $this->l('Setup following links as cronjobs (it is recommended to run the cronjobs once a day)') . ':</strong><br>';
            if (Tools::version_compare(_PS_VERSION_, '1.7.4', '>=')) {
                $out .= $this->displayInformation($text . \implode('<br>', $cron));
            } else {
                $out .= $this->displayConfirmation($text . \implode('<br>', $cron));
            }
        }

        // Return the output
        return $out .
        $this->renderForm() .
        $this->display(__FILE__, 'views/templates/admin/scripts.tpl') .
        $this->analyzeSystem() .
        $this->analyzePhpIni() .
        $this->display(__FILE__, 'views/templates/admin/ssl.tpl') .
        $this->display(__FILE__, 'views/templates/admin/contact.tpl');
    }

    /**
     * Hook stuff in front office header.
     *
     * @param array $params
     */
    public function hookDisplayHeader($params)
    {
        // Disable browser features
        if ('2' === Configuration::get('LITE_DISABLE_RIGHT_CLICK')) {
            $this->context->controller->addJS($this->_path . 'views/js/contextmenu.js');
        } elseif ('3' === Configuration::get('LITE_DISABLE_RIGHT_CLICK')) {
            $this->context->controller->addJS($this->_path . 'views/js/contextmenu-img.js');
        }

        // Ban IP addresses
        if (true === (bool) Configuration::get('LITE_BAN_IP_ACTIVATE') && !Tools::isEmpty(Configuration::get('LITE_BAN_IP')) && false !== Configuration::get('LITE_BAN_IP')) {
            if (true === $this->blockIp()) {
                $this->blockRequest();
            }
        }

        // Block user agents
        if (true === (bool) Configuration::get('LITE_BLOCK_USER_AGENT_ACTIVATE') && !Tools::isEmpty(Configuration::get('LITE_BLOCK_USER_AGENT')) && false !== Configuration::get('LITE_BLOCK_USER_AGENT')) {
            if (true === $this->blockUserAgent()) {
                $this->blockRequest();
            }
        }
    }

    /**
     * Hook stuff in back office header.
     *
     * @param array $params
     */
    public function hookDisplayBackOfficeTop($params)
    {
        $this->context->controller->addCss($this->_path . 'views/css/menuTabIcon.css');

        if ('securitylite' === Tools::getValue('configure')) {
            $this->context->controller->addJS($this->_path . 'views/js/secure-random-password.min.js');
        }

        if (true === (bool) Configuration::get('LITE_FAIL2BAN')) {
            $email = Tools::getValue('email');
            $passwd = Tools::getValue('passwd');
            $findTime = (int) Configuration::get('LITE_FIND_TIME') * 60;
            $eldestAccessTime = $this->getEldestAccessTry($email);

            if (Tools::isSubmit('submitLogin') && $email && $passwd) {
                $banTime = (int) Configuration::get('LITE_BAN_TIME') * 60;
                $employeeBanTime = $this->getBanTime($email);

                if (\time() - $employeeBanTime <= $banTime) {
                    $this->ban();
                }
                $employee = new Employee();
                $isLoaded = $employee->getByEmail($email, $passwd);

                if (!$isLoaded) {
                    Db::getInstance()->insert('securitylite', [
                        'email' => $email,
                        'ip' => \Tools::getRemoteAddr(),
                    ]);
                }

                if ($eldestAccessTime && \time() - $eldestAccessTime <= $findTime) {
                    Db::getInstance()->insert('securitylite', [
                        'email' => $email,
                        'ip' => \Tools::getRemoteAddr(),
                        'banned' => 1,
                    ]);
                    $this->ban();
                }
            }
        }
    }

    /**
     * Creates a new backup file.
     *
     * @return bool true on successful backup
     */
    public function backupDatabase()
    {
        if (false === (bool) Configuration::get('LITE_BACKUP_DB') && false === (bool) Configuration::get('LITE_BACKUP_DB_DROPBOX')) {
            return false;
        }

        $dirBackupDatabase = '/backup/database/';

        $ignore_insert_table = [
            _DB_PREFIX_ . 'connections',
            _DB_PREFIX_ . 'connections_page',
            _DB_PREFIX_ . 'connections_source',
            _DB_PREFIX_ . 'guest',
            _DB_PREFIX_ . 'statssearch',
        ];

        // Generate some random number, to make it extra hard to guess backup file names
        $rand = Tools::strtolower(Tools::passwdGen(16));
        $date = \time();

        $backupFile = _PS_MODULE_DIR_ . $this->name . $dirBackupDatabase . $date . '-' . $rand . '.sql';

        // Figure out what compression is available and open the file
        if (\function_exists('bzopen')) {
            $backupFile .= '.bz2';
            $fp = @bzopen($backupFile, 'w');
        } elseif (\function_exists('gzopen')) {
            $backupFile .= '.gz';
            $fp = @\gzopen($backupFile, 'w');
        } else {
            $fp = @\fopen($backupFile, 'wb');
        }

        if (false === $fp) {
            return false;
        }

        $this->id = \realpath($backupFile);

        \fwrite($fp, '/* Backup for ' . Tools::getHttpHost(false, false) . __PS_BASE_URI__ . "\n *  at " . \date($date) . "\n */\n");
        \fwrite($fp, "\n" . 'SET NAMES \'utf8\';');
        \fwrite($fp, "\n" . 'SET FOREIGN_KEY_CHECKS = 0;');
        \fwrite($fp, "\n" . 'SET SESSION sql_mode = \'\';' . "\n\n");

        // Find all tables
        $tables = Db::getInstance()->executeS('SHOW TABLES');
        $found = 0;
        foreach ($tables as $table) {
            $table = \current($table);

            // Skip tables which do not start with _DB_PREFIX_
            if (\Tools::strlen($table) < \Tools::strlen(_DB_PREFIX_) || 0 !== \strncmp($table, _DB_PREFIX_, \Tools::strlen(_DB_PREFIX_))) {
                continue;
            }

            // Export the table schema
            $schema = Db::getInstance()->executeS('SHOW CREATE TABLE `' . $table . '`');

            if (1 !== \count($schema) || !isset($schema[0]['Table']) || !isset($schema[0]['Create Table'])) {
                \fclose($fp);

                return false;
            }

            \fwrite($fp, '/* Scheme for table ' . $schema[0]['Table'] . " */\n");

            \fwrite($fp, $schema[0]['Create Table'] . ";\n\n");

            if (!\in_array($schema[0]['Table'], $ignore_insert_table, true)) {
                $data = Db::getInstance()->query('SELECT * FROM `' . $schema[0]['Table'] . '`', false);
                $sizeof = Db::getInstance()->numRows();
                $lines = \explode("\n", $schema[0]['Create Table']);

                if ($data && $sizeof > 0) {
                    // Export the table data
                    \fwrite($fp, 'INSERT INTO `' . $schema[0]['Table'] . "` VALUES\n");
                    $i = 1;
                    while ($row = Db::getInstance()->nextRow($data)) {
                        $s = '(';

                        foreach ($row as $field => $value) {
                            $tmp = "'" . pSQL($value, true) . "',";
                            if ("''," !== $tmp) {
                                $s .= $tmp;
                            } else {
                                foreach ($lines as $line) {
                                    if (false !== \mb_strpos($line, '`' . $field . '`')) {
                                        if (\preg_match('/(.*NOT NULL.*)/Ui', $line)) {
                                            $s .= "'',";
                                        } else {
                                            $s .= 'NULL,';
                                        }

                                        break;
                                    }
                                }
                            }
                        }
                        $s = \rtrim($s, ',');

                        if (0 === $i % 200 && $i < $sizeof) {
                            $s .= ");\nINSERT INTO `" . $schema[0]['Table'] . "` VALUES\n";
                        } elseif ($i < $sizeof) {
                            $s .= "),\n";
                        } else {
                            $s .= ");\n";
                        }

                        \fwrite($fp, $s);
                        ++$i;
                    }
                }
            }
            ++$found;
        }

        \fclose($fp);

        $backupSaved = (int) Configuration::get('LITE_BACKUP_DB_SAVED');

        if (0 === $backupSaved) {
            return true;
        }

        if (false === (bool) Configuration::get('LITE_BACKUP_DB')) {
            Tools::deleteFile($backupFile);
        } else {
            $this->deleteOldBackups($backupSaved, $dirBackupDatabase);
        }

        return true;
    }

    /**
     * Delete old backups from local.
     *
     * @param $backupSaved
     * @param $dir
     */
    public function deleteOldBackups($backupSaved, $dir)
    {
        $ext = [
            'bz2',
            'gz',
            'zip',
        ];
        $backupFile = [];

        if ($handle = \opendir(_PS_MODULE_DIR_ . $this->name . $dir)) {
            while (false !== ($entry = \readdir($handle))) {
                if ('.' !== $entry && '..' !== $entry) {
                    if (\in_array(\pathinfo(\basename($entry), \PATHINFO_EXTENSION), $ext, true)) {
                        $backupFile[] = $entry;
                    }
                }
            }
            if (!empty($backupFile)) {
                $x = \count($backupFile);
                $y = 0;
                while ($x > $backupSaved) {
                    Tools::deleteFile(_PS_MODULE_DIR_ . $this->name . $dir . $backupFile[$y]);
                    --$x;
                    ++$y;
                }
            }
            \closedir($handle);
        }
    }

    /**
     * Lookup ban time for specific e-mail in database.
     *
     * @param string $email
     *
     * @return int
     */
    public function getBanTime($email)
    {
        $sql = new DbQuery();
        $sql->select('MAX(access_time) AS access_time');
        $sql->from('securitylite');
        $sql->where('banned = 1');
        $sql->where(\sprintf('email = "%s"', pSQL($email)));
        $result = Db::getInstance()->executeS($sql);

        return $result ? \strtotime($sql) : 0;
    }

    /**
     * Install tab.
     */
    public function installTab()
    {
        $tab = new Tab();

        $tab->module = $this->name;

        $languages = \Language::getLanguages(false);
        $name = [];
        foreach ($languages as $language) {
            $name[$language['id_lang']] = 'Security Lite';
        }

        $tab->name = $name;
        $tab->class_name = 'AdminSecurityLite';

        if (Tools::version_compare(_PS_VERSION_, '1.7.0', '>=')) {
            $tab->icon = 'security';
            $tab->id_parent = (int) Tab::getIdFromClassName('IMPROVE');
            $tab->save();
        } else {
            $tab->id_parent = 0;
            $tab->add();
        }
    }

    /**
     * Uninstall tab.
     */
    public function uninstallTab()
    {
        $tabId = (int) Tab::getIdFromClassName('AdminSecurityLite');
        if (!$tabId) {
            return true;
        }

        $tab = new Tab($tabId);

        return $tab->delete();
    }

    /**
     * Build form.
     *
     * @return array
     */
    protected function renderForm()
    {
        $helper = new HelperForm();
        $helper->show_toolbar = false;
        $helper->table = $this->table;
        $helper->module = $this;
        $helper->default_form_language = $this->context->language->id;
        $helper->allow_employee_form_lang = (bool) Configuration::get('PS_BO_ALLOW_EMPLOYEE_FORM_LANG', false);
        $helper->identifier = $this->identifier;
        $helper->submit_action = 'submitSecurityLiteModule';
        $helper->currentIndex = $this->context->link->getAdminLink('AdminModules', false) . '&configure=securitylite&tab_module=' . $this->tab;
        $helper->token = \Tools::getAdminTokenLite('AdminModules');
        $helper->tpl_vars = [
            'fields_value' => $this->getConfigFormValues(),
            'languages' => $this->context->controller->getLanguages(),
            'id_language' => $this->context->language->id,
        ];

        if (!\defined('_TB_VERSION_')) {
            $displayForms = [
                $this->fieldsFormSecuritySettings(),
                $this->fieldsFormBackup(),
                $this->fieldsFormAdminDir(),
                $this->fieldsFormPasswdGen(),
            ];
        } else {
            $displayForms = [
                $this->fieldsFormSecuritySettings(),
                $this->fieldsFormBackup(),
                $this->fieldsFormPasswdGen(),
            ];
        }

        return $helper->generateForm($displayForms);
    }

    /**
     * Build forms.
     */
    protected function fieldsFormAdminDir()
    {
        return [
            'form' => [
                'legend' => [
                    'title' => $this->l('Admin directory'),
                    'icon' => 'icon-folder-o',
                ],
                'input' => [
                    [
                        'disabled' => true,
                        'type' => 'switch',
                        'label' => $this->l('Are you sure, you want to change name of admin directory?'),
                        'name' => 'LITE_ADMIN_DIRECTORY',
                        'is_bool' => true,
                        'desc' => $this->proFeature . $this->l('You will be redirected to the new URL once you click') . ' "' . $this->l('Save') . '" ' . $this->l('if this is set to') . ' "' . $this->l('Yes') . '"',
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
                        'disabled' => true,
                        'col' => 4,
                        'type' => 'text',
                        'prefix' => $this->getBaseURL(),
                        'desc' => $this->proFeature . $this->l('Your admin directory name should include both letters and numbers. Make it hard to guess; don\'t use something like admin123, administrator, backoffice etc.') . ' <a onclick="" href ="javascript:void(0)">' . $this->l('Generate secure directory name') . '</a>.',
                        'name' => 'LITE_ADMIN_DIRECTORY_NAME',
                        'label' => $this->l('Directory name'),
                        'hint' => $this->l('Accepted characters') . ': "a-z A-Z 0-9 _ . -"',
                    ],
                ],
                'submit' => [
                    'title' => $this->l('Save'),
                ],
            ],
        ];
    }

    /**
     * Build forms.
     */
    protected function fieldsFormBackup()
    {
        $dirBackupDatabase = '/backup/database/';
        $dirBackupFiles = '/backup/files/';

        $featured = [];

        $featuredFiles = [];

        $list = [];
        $listFiles = [];

        if (!empty($featured)) {
            foreach ($featured as $value) {
                $list[] = $value['path_lower'] . ' (' . \date('Y-m-d', \Tools::substr(\basename($value['path_lower']), 0, 10)) . ')';
            }
        }

        if (!empty($featuredFiles)) {
            foreach ($featuredFiles as $valueFiles) {
                $listFiles[] = $valueFiles['path_lower'] . ' (' . \date('Y-m-d', \Tools::substr(\basename($valueFiles['path_lower']), 0, 10)) . ')';
            }
        }

        $backupDir = _PS_MODULE_DIR_ . 'securitylite/backup';
        if (!\is_dir($backupDir . '/database')) {
            \mkdir($backupDir . '/database', 0755, true);
        }
        if (!\is_dir($backupDir . '/files')) {
            \mkdir($backupDir . '/files', 0755, true);
        }
        $this->addIndexRecursively($backupDir);

        $dirPath = [];
        $ext = ['bz2', 'gz'];
        if ($handle = \opendir(_PS_MODULE_DIR_ . $this->name . $dirBackupDatabase)) {
            while (false !== ($entry = \readdir($handle))) {
                if ('.' !== $entry && '..' !== $entry) {
                    if (\in_array(\pathinfo(\basename($entry), \PATHINFO_EXTENSION), $ext, true)) {
                        $dirPath[] = \realpath(_PS_MODULE_DIR_ . $this->name . $dirBackupDatabase . $entry) . ' (' . \date('Y-m-d', \Tools::substr(\basename($entry), 0, 10)) . ')';
                    }
                }
            }
        }

        $filePath = [];
        if ($handle = \opendir(_PS_MODULE_DIR_ . $this->name . $dirBackupFiles)) {
            while (false !== ($entry = \readdir($handle))) {
                if ('.' !== $entry && '..' !== $entry) {
                    if ('zip' === \pathinfo(\basename($entry), \PATHINFO_EXTENSION)) {
                        $filePath[] = \realpath(_PS_MODULE_DIR_ . $this->name . $dirBackupFiles . $entry) . ' (' . \date('Y-m-d', \Tools::substr(\basename($entry), 0, 10)) . ')';
                    }
                }
            }
        }

        return [
            'form' => [
                'legend' => [
                    'title' => $this->l('Automatic backups'),
                    'icon' => 'icon-files-o',
                ],
                'description' => $this->l('Security Lite is not responsible for your database/files, its backups and/or recovery.') . '<br>' .
                $this->l('You should back up your data on a regular basis (both files and database).') . '<br>' .
                $this->l('Security Lite can back up your database and files and save it local and to Dropbox.') . '<br>' .
                $this->l('Always verify the quality and integrity of your backup files!') . '<br>' .
                $this->l('Always verify that your backup files are complete, up-to-date and valid, even if you had a success message appear during the backup process.') . '<br>' .
                $this->l('Always check your data.') . '<br>' .
                $this->l('Never restore a backup on a live site.'),
                'input' => [
                    [
                        'disabled' => true,
                        'col' => 5,
                        'type' => 'text',
                        'desc' => $this->proFeature . $this->l('You must set up your Dropbox access token before you can activate backup to Dropbox. Get your access token here') . ': <a href="https://www.dropbox.com/developers/apps" target="_blank" rel="noopener noreferrer">' . $this->l('Get access token') . '</a>. ' . $this->l('You will have to register to get a token, but it\'s free.'),
                        'name' => 'LITE_BACKUP_DB_TOKEN',
                        'label' => $this->l('Dropbox access token'),
                        'prefix' => '<i class="icon-dropbox"></i>',
                        'hint' => $this->l('Your Dropbox token'),
                        'required' => true,
                    ],
                    [
                        'disabled' => true,
                        'type' => 'switch',
                        'label' => $this->l('Backup database to Dropbox'),
                        'name' => 'LITE_BACKUP_DB_DROPBOX',
                        'is_bool' => true,
                        'desc' => $this->proFeature . $this->l('Save a backup of your database to your Dropbox. Statistical data are excluded.') . ' ' . $this->l('Once this option is enabled, you will get a link you have set up as a cronjob.') . '<br><strong>' . (!empty($list) ? $this->l('You can find the path to your backups below') . ':<br>' . \implode('<br>', $list) : $this->l('You have no backups yet.')) . '</strong>',
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
                        'type' => 'switch',
                        'label' => $this->l('Backup database to local'),
                        'name' => 'LITE_BACKUP_DB',
                        'is_bool' => true,
                        'desc' => $this->l('Save a local backup of your database. Statistical data are excluded.') . ' ' . $this->l('Once this option is enabled, you will get a link you have set up as a cronjob.') . '<br><strong>' . (!empty($dirPath) ? $this->l('You can find the path to your backups below') . ':<br>' . \implode('<br>', $dirPath) : $this->l('You have no backups yet.')) . '</strong>',
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
                        'type' => 'text',
                        'prefix' => '<i class="icon-floppy-o"></i>',
                        'desc' => $this->l('Old backups will be deleted when newer one is generated. How many backups do you want to keep at the time? Write "0" for unlimited backups.'),
                        'name' => 'LITE_BACKUP_DB_SAVED',
                        'label' => $this->l('Database backups to save'),
                        'suffix' => $this->l('backups'),
                        'hint' => $this->l('Must be an integer'),
                        'required' => true,
                    ],
                    [
                        'disabled' => true,
                        'type' => 'switch',
                        'label' => $this->l('Backup files to Dropbox'),
                        'name' => 'LITE_BACKUP_FILE_DROPBOX',
                        'is_bool' => true,
                        'desc' => $this->proFeature . $this->l('Save a full backup of your files to your Dropbox. Cache and log files are excluded.') . ' ' . $this->l('Once this option is enabled, you will get a link you have set up as a cronjob.') . '<br><strong>' . (!empty($listFiles) ? $this->l('You can find the path to your backups below') . ':<br>' . \implode('<br>', $listFiles) : $this->l('You have no backups yet.')) . '</strong>',
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
                        'disabled' => true,
                        'type' => 'switch',
                        'label' => $this->l('Backup files to local'),
                        'name' => 'LITE_BACKUP_FILE',
                        'is_bool' => true,
                        'desc' => $this->proFeature . $this->l('Save a full backup of your files on your PrestaShop installation.') . ' ' . $this->l('Once this option is enabled, you will get a link you have set up as a cronjob.') . '<br><strong>' . (!empty($filePath) ? $this->l('You can find the path to your backups below') . ':<br>' . \implode('<br>', $filePath) : $this->l('You have no backups yet.')) . '</strong>',
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
                        'disabled' => true,
                        'col' => 2,
                        'type' => 'text',
                        'prefix' => '<i class="icon-floppy-o"></i>',
                        'desc' => $this->proFeature . $this->l('Old backups will be deleted if newer one is generated. How many backups do you want to keep at the time? Write "0" for unlimited backups.'),
                        'name' => 'LITE_BACKUP_FILE_SAVED',
                        'label' => $this->l('File backups to save'),
                        'suffix' => $this->l('backups'),
                        'hint' => $this->l('Must be an integer'),
                        'required' => true,
                    ],
                    [
                        'disabled' => true,
                        'type' => 'select',
                        'label' => $this->l('Zip compression level for file backup'),
                        'desc' => $this->proFeature . $this->l('The values range from 1 (super-fast) to 9 (maximum) are supported. The higher the number, the better and longer the compression.'),
                        'name' => 'LITE_BACKUP_COMPRESSION',
                        'options' => [
                            'query' => [
                                [
                                    'id_option' => 'SUPER_FAST',
                                    'name' => '1 ' . $this->l('super-fast'),
                                ],
                                [
                                    'id_option' => 'NORMAL',
                                    'name' => '5 ' . $this->l('normal'),
                                ],
                                [
                                    'id_option' => 'MAXIMUM',
                                    'name' => '9 ' . $this->l('maximum'),
                                ],
                            ],
                            'id' => 'id_option',
                            'name' => 'name',
                        ],
                    ],
                ],
                'submit' => [
                    'title' => $this->l('Save'),
                ],
            ],
        ];
    }

    /**
     * Build forms.
     */
    protected function fieldsFormPasswdGen()
    {
        return [
            'form' => [
                'legend' => [
                    'title' => $this->l('Password generator'),
                    'icon' => 'icon-key',
                ],
                'description' => $this->l('You should use a strong and unique password for each of: MySQL database, FTP, hosting panel/cPanel, SSH access and back office. You can use this tool to generate the passwords.'),
                'input' => [
                    [
                        'col' => 4,
                        'type' => 'textbutton',
                        'label' => $this->l('Generate strong password'),
                        'desc' => $this->l('The password is not saved anywhere by this module.'),
                        'name' => 'LITE_PASSWORD_GENERATOR',
                        'button' => [
                            'label' => $this->l('Generate'),
                            'attributes' => [
                                'onclick' => 'add_field();',
                            ],
                        ],
                    ],
                ],
            ],
        ];
    }

    /**
     * Build forms.
     */
    protected function fieldsFormSecuritySettings()
    {
        $tfa = new RobThree\Auth\TwoFactorAuth(Configuration::get('PS_SHOP_NAME'), 6, 30, 'sha1');
        $linkGoogleApi = 'https://www.google.com/recaptcha/admin/create';
        $linkHoneypotApi = 'https://www.projecthoneypot.org/httpbl_configure.php';

        return [
            'form' => [
                'legend' => [
                    'title' => $this->l('Security settings'),
                    'icon' => 'icon-cogs',
                ],
                'tabs' => [
                    'protectBackOffice' => '<i class="icon-lock"></i> ' . $this->l('Brute force protection'),
                    'tfa' => '<i class="icon-key"></i> ' . $this->l('Two-Factor Authentication'),
                    'secondLogin' => '<i class="icon-sign-in"></i> ' . $this->l('Second login'),
                    'secureFrontOffice' => '<i class="icon-shield"></i> ' . $this->l('HTTP headers'),
                    'antiSpam' => '<i class="icon-user-secret"></i> ' . $this->l('Anti-SPAM'),
                    'permissions' => '<i class="icon-file-o"></i> ' . $this->l('Permissions'),
                    'index' => '<i class="icon-sitemap"></i> ' . $this->l('Index'),
                    'antiVirus' => '<i class="icon-ban"></i> ' . $this->l('Anti-virus'),
                    'firewall' => '<i class="icon-repeat"></i> ' . $this->l('Firewall (WAF)'),
                    'protectContent' => '<i class="icon-hand-o-up"></i> ' . $this->l('Protect content'),
                ],
                'input' => [
                    [
                        'col' => 6,
                        'tab' => 'protectBackOffice',
                        'type' => 'switch',
                        'label' => $this->l('Activate brute force protection'),
                        'name' => 'LITE_FAIL2BAN',
                        'is_bool' => true,
                        'desc' => $this->l('A brute force attack is the simplest method to gain access to a site. The hacker tries various combinations of usernames and passwords again and again until he gets in. Enable this feature to limits the maximum amount of tries to your back office.'),
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
                        'desc' => $this->l('Wrong answers before ban.'),
                        'name' => 'LITE_MAX_RETRY',
                        'prefix' => '<i class="icon-repeat"></i>',
                        'suffix' => $this->l('times'),
                        'label' => $this->l('Max retry'),
                        'hint' => $this->l('Must be an integer'),
                        'required' => true,
                    ],
                    [
                        'col' => 2,
                        'tab' => 'protectBackOffice',
                        'type' => 'text',
                        'desc' => $this->l('A host is banned if it has generated') . ' "' . $this->l('Max retry') . '" ' . $this->l('during the last') . ' "' . $this->l('Request timeout') . '" ' . $this->l('Enter time in minutes') . '.',
                        'name' => 'LITE_FIND_TIME',
                        'prefix' => '<i class="icon-clock-o"></i>',
                        'suffix' => $this->l('minutes'),
                        'label' => $this->l('Request timeout'),
                        'hint' => $this->l('Must be an integer'),
                        'required' => true,
                    ],
                    [
                        'col' => 2,
                        'tab' => 'protectBackOffice',
                        'type' => 'text',
                        'desc' => $this->l('Time a host is banned. Enter time in minutes.'),
                        'name' => 'LITE_BAN_TIME',
                        'prefix' => '<i class="icon-clock-o"></i>',
                        'suffix' => $this->l('minutes'),
                        'label' => $this->l('Ban time'),
                        'hint' => $this->l('Must be an integer'),
                        'required' => true,
                    ],
                    [
                        'disabled' => true,
                        'tab' => 'protectBackOffice',
                        'type' => 'switch',
                        'label' => $this->l('Receive e-mail on fail to login'),
                        'name' => 'LITE_SEND_MAIL',
                        'is_bool' => true,
                        'desc' => $this->proFeature . $this->l('Receive an e-mail in case someone input a wrong password. This setting can only be enabled if brute force protection is activated.'),
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
                        'disabled' => true,
                        'tab' => 'protectBackOffice',
                        'type' => 'switch',
                        'label' => $this->l('Receive e-mail on successfully login'),
                        'name' => 'LITE_SEND_MAIL_LOGIN',
                        'is_bool' => true,
                        'desc' => $this->proFeature . $this->l('Receive an e-mail in case someone input the correct password. This setting can only be enabled if brute force protection is activated.'),
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
                        'disabled' => true,
                        'col' => 3,
                        'tab' => 'protectBackOffice',
                        'type' => 'text',
                        'desc' => $this->proFeature . $this->l('Enter the e-mail which you would like to be notified at.'),
                        'name' => 'LITE_FAIL2BAN_EMAIL',
                        'prefix' => '<i class="icon-envelope-o"></i>',
                        'label' => $this->l('E-mail'),
                        'hint' => $this->l('Must be a valid e-mail address'),
                        'required' => true,
                    ],
                    [
                        'disabled' => true,
                        'tab' => 'protectBackOffice',
                        'type' => 'textbutton',
                        'col' => 6,
                        'desc' => $this->proFeature . $this->l('You can list your own IP addresses to avoid getting an e-mail if you write the password wrong. You can still get banned for a period of time if you fail to login according to your own rules above.') . '<br>' . $this->l('The module can handle IPv4, IPv6 addresses, as well as IP ranges, in CIDR formats') . ' (' . $this->l('like') . ' <code>::1/128</code> ' . $this->l('or') . ' <code>127.0.0.1/32</code>) ' . $this->l('and in pattern format') . ' (' . $this->l('like') . ' <code>::*:*</code> ' . $this->l('or') . ' <code>127.0.*.*</code>). ' . $this->l('Separate by comma (\',\').'),

                        'name' => 'LITE_WHITELIST_IPS',
                        'button' => [
                            'label' => '<i class="icon-plus"></i> ' . $this->l('Add my IP'),
                            'attributes' => [
                                'onclick' => '',
                            ],
                        ],
                        'label' => $this->l('Whitelist IP addresses'),
                        'hint' => $this->l('E.g.') . ' 123.456.789,123.456.*,123.*,...',
                    ],
                    [
                        'disabled' => true,
                        'tab' => 'protectBackOffice',
                        'type' => 'switch',
                        'label' => $this->l('Activate log'),
                        'name' => 'LITE_FAIL2BAN_LOG',
                        'is_bool' => true,
                        'desc' => $this->proFeature . $this->l('Record banned users into a log file.'),
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
                        'disabled' => true,
                        'tab' => 'secureFrontOffice',
                        'type' => 'switch',
                        'label' => $this->l('Click-jack protection'),
                        'name' => 'LITE_CLICK_JACKING',
                        'is_bool' => true,
                        'desc' => $this->proFeature . $this->l('Prevent browsers from framing your site. This will defend you against attacks like click-jacking.'),
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
                        'disabled' => true,
                        'tab' => 'secureFrontOffice',
                        'type' => 'switch',
                        'label' => $this->l('XSS protection'),
                        'name' => 'LITE_X_XSS_PPROTECTION',
                        'is_bool' => true,
                        'desc' => $this->proFeature . $this->l('Set secure configuration for the cross-site scripting filters built into most browsers.'),
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
                        'disabled' => true,
                        'tab' => 'secureFrontOffice',
                        'type' => 'switch',
                        'label' => $this->l('Disable content sniffing'),
                        'name' => 'LITE_X_CONTENT_TYPE_OPTIONS',
                        'is_bool' => false,
                        'desc' => $this->proFeature . $this->l('Stop browsers from trying to MIME-sniff the content type and forces it to stick with the declared content-type.'),
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
                        'disabled' => true,
                        'tab' => 'secureFrontOffice',
                        'type' => 'switch',
                        'label' => $this->l('Force secure connection with HSTS'),
                        'name' => 'LITE_STRICT_TRANSPORT_SECURITY',
                        'is_bool' => true,
                        'desc' => $this->proFeature . $this->l('Strengthens your implementation of TLS by getting the user agent to enforce the use of HTTPS.'),
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
                        'disabled' => true,
                        'tab' => 'secureFrontOffice',
                        'type' => 'checkbox',
                        'desc' => $this->proFeature . $this->l('Please follow this link to understand these settings: ') . '<a href="https://hstspreload.org/?domain=' . $this->getShopUrl() . '" target="_blank" rel="noopener noreferrer"> https://hstspreload.org/?domain=' . $this->getShopUrl() . '</a>.',
                        'label' => $this->l('HSTS settings'),
                        'name' => 'LITE_HSTS_SETTINGS',
                        'values' => [
                            'query' => [
                                [
                                    'id_option' => '0',
                                    'name' => 'Preload',
                                    'value' => 0,
                                ],
                                [
                                    'id_option' => '1',
                                    'name' => 'Include subdomains',
                                    'value' => 1,
                                ],
                            ],
                            'id' => 'id_option',
                            'name' => 'name',
                            'value' => 'value',
                        ],
                    ],
                    [
                        'disabled' => true,
                        'tab' => 'secureFrontOffice',
                        'type' => 'switch',
                        'label' => $this->l('Expect CT'),
                        'name' => 'LITE_EXPECT_CT',
                        'is_bool' => true,
                        'desc' => $this->proFeature . $this->l('Signals to the user agent that compliance with the certificate transparency policy should be enforced.'),
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
                        'disabled' => true,
                        'tab' => 'secureFrontOffice',
                        'type' => 'switch',
                        'label' => $this->l('Referrer policy'),
                        'name' => 'LITE_REFFERER_POLICY',
                        'is_bool' => true,
                        'desc' => $this->proFeature . $this->l('The browser will only set the referrer header on requests to the same origin. If the destination is another origin then no referrer information will be sent.') . '<br><br><br><a class="btn btn-default" style="font-style: normal;" href="https://securityheaders.com/?q=' . $this->getShopUrl() . '&amp;hide=on&amp;followRedirects=on" target="_blank" rel="noopener noreferrer">Analyze security HTTP headers</a><br>' . $this->l('Security Pro can fix all warnings and errors reported by') . ' https://securityheaders.com; ' . $this->l('you can get an') . ' <strong style="color: green;">A+</strong> ' . $this->l('score') . '!',
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
                        'disabled' => true,
                        'col' => 6,
                        'tab' => 'secondLogin',
                        'type' => 'switch',
                        'label' => $this->l('Activate second login'),
                        'name' => 'LITE_HTPASSWD',
                        'is_bool' => true,
                        'desc' => $this->proFeature . $this->l('Even if your back office is already secured by PrestaShop\'s login, you might want to add another layer of security from your webserver itself. This is done using .htpasswd (Apache-servers only).'),
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
                        'disabled' => true,
                        'col' => 3,
                        'tab' => 'secondLogin',
                        'type' => 'text',
                        'prefix' => '<i class="icon-user"></i>',
                        'desc' => $this->proFeature . $this->l('You should use another username than you do for your regular back office login.') . ' <a onclick="add_field3()" href ="javascript:void(0)">' . $this->l('Generate secure username') . '</a>.',
                        'name' => 'LITE_HTPASSWD_USER',
                        'label' => $this->l('Username'),
                        'hint' => $this->l('Invalid character') . ': ":"',
                    ],
                    [
                        'disabled' => true,
                        'col' => 3,
                        'tab' => 'secondLogin',
                        'type' => 'text',
                        'prefix' => '<i class="icon-key"></i>',
                        'desc' => $this->proFeature . $this->l('You should use another password than you do for your regular back office login.') . ' <a onclick="add_field4()" href ="javascript:void(0)">' . $this->l('Generate secure password') . '</a>.',
                        'name' => 'LITE_HTPASSWD_PASS',
                        'label' => $this->l('Password'),
                        'hint' => $this->l('Invalid character') . ': ":"',
                    ],
                    [
                        'disabled' => true,
                        'tab' => 'antiSpam',
                        'type' => 'switch',
                        'col' => 6,
                        'label' => $this->l('Prevent fake accounts'),
                        'name' => 'LITE_FAKE_ACCOUNTS',
                        'is_bool' => true,
                        'desc' => $this->proFeature . $this->l('Prevent bots from making fake accounts by setting a token and verify that first name and last name is not an URL.'),
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
                        'disabled' => true,
                        'tab' => 'antiSpam',
                        'type' => 'switch',
                        'col' => 6,
                        'label' => $this->l('Disable contact form'),
                        'name' => 'LITE_DISABLE_CONTACT_FORM',
                        'is_bool' => true,
                        'desc' => $this->proFeature . $this->l('Sometimes you just want to leave a simple e-mail link in your footer and let users use their own e-mail client to send e-mails instead of the built-in contact form. If you want to disable the contact form you can enable this feature.'),
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
                        'disabled' => true,
                        'tab' => 'antiSpam',
                        'type' => 'switch',
                        'col' => 6,
                        'label' => $this->l('Block TOR IPv4 and IPv6 addresses'),
                        'name' => 'LITE_BLOCK_TOR',
                        'is_bool' => true,
                        'desc' => $this->proFeature . $this->l('In some cases, TOR browsers are used by criminals to hide themselves while buying from a stolen credit card. If you are having this problem, you can block TOR IPv4/IPv6 addresses with this feature.'),
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
                        'tab' => 'antiSpam',
                        'type' => 'switch',
                        'col' => 6,
                        'label' => $this->l('Block custom list of IP addresses'),
                        'name' => 'LITE_BAN_IP_ACTIVATE',
                        'is_bool' => true,
                        'desc' => $this->l('Block hosts with below IP addresses from your website. You cannot block hosts that are already on this') . ' <a href="' . $this->context->link->getAdminLink('AdminGeolocation') . ' " target="_blank" rel="noopener noreferrer">' . $this->l('whitelist') . '</a>. ' . $this->l('If you want to ban a country, please use this built-in PrestaShop feature') . ': <a href="' . $this->context->link->getAdminLink('AdminGeolocation') . ' " target="_blank" rel="noopener noreferrer">' . $this->l('Ban countries') . '</a>. ',
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
                        'tab' => 'antiSpam',
                        'type' => 'text',
                        'col' => 6,
                        'desc' => $this->l('The module can handle IPv4, IPv6 addresses, as well as IP ranges, in CIDR formats') . '( ' . $this->l('like') . ' <code>::1/128</code> ' . $this->l('or') . ' <code>127.0.0.1/32</code>) ' . $this->l('and in pattern format') . ' (' . $this->l('like') . ' <code>::*:*</code> ' . $this->l('or') . ' <code>127.0.*.*</code>). ' . $this->l('Separate by comma (\',\').'),
                        'name' => 'LITE_BAN_IP',
                        'label' => $this->l('Custom list of IP addresses'),
                        'hint' => $this->l('E.g.') . ' 123.456.789,123.456.*,123.*,...',
                    ],
                    [
                        'tab' => 'antiSpam',
                        'type' => 'switch',
                        'col' => 4,
                        'label' => $this->l('Block custom list of user agents'),
                        'name' => 'LITE_BLOCK_USER_AGENT_ACTIVATE',
                        'is_bool' => true,
                        'desc' => $this->l('Block user agents with below names from your website.'),
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
                        'tab' => 'antiSpam',
                        'type' => 'text',
                        'col' => 6,
                        'desc' => $this->l('Separate by comma (\',\').'),
                        'name' => 'LITE_BLOCK_USER_AGENT',
                        'label' => $this->l('Custom list of User agents'),
                        'hint' => $this->l('E.g.') . ' 360Spider,Alexibot,BackWeb,...',
                    ],
                    [
                        'disabled' => true,
                        'tab' => 'antiVirus',
                        'type' => 'switch',
                        'col' => 6,
                        'label' => $this->l('Get an e-mail if file changes'),
                        'name' => 'LITE_FILE_CHANGES_EMAIL',
                        'is_bool' => true,
                        'desc' => $this->proFeature . $this->l('Track every file change on your server and let you know by e-mail if something has changed.') . ' ' . $this->l('Once this option is enabled, you will get a link you have set up as a cronjob.'),
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
                        'disabled' => true,
                        'tab' => 'antiVirus',
                        'type' => 'switch',
                        'col' => 6,
                        'label' => $this->l('Log filechanges'),
                        'name' => 'LITE_FILE_CHANGES_LOG',
                        'is_bool' => true,
                        'desc' => $this->proFeature . $this->l('Track every file change on your server and log it if something has changed.'),
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
                        'disabled' => true,
                        'tab' => 'antiVirus',
                        'type' => 'text',
                        'col' => 6,
                        'desc' => $this->proFeature . $this->l('Whitelist dynamic files') . '. ' . $this->l('Separate files by comma (\',\')') . '.',
                        'name' => 'LITE_FILE_CHANGES_WHITELIST',
                        'label' => $this->l('Whitelist filter for file changes'),
                        'hint' => $this->l('E.g.') . ' file.json,file.xml',
                    ],
                    [
                        'disabled' => true,
                        'tab' => 'antiVirus',
                        'type' => 'switch',
                        'col' => 6,
                        'label' => $this->l('Get an e-mail if malware is detected'),
                        'name' => 'LITE_MALWARE_SCAN_EMAIL',
                        'is_bool' => true,
                        'desc' => $this->proFeature . $this->l('Scan all your directories for malicious code and let you know by e-mail if something is found.') . ' ' . $this->l('Once this option is enabled, you will get a link you have set up as a cronjob.'),
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
                        'disabled' => true,
                        'tab' => 'antiVirus',
                        'type' => 'switch',
                        'col' => 6,
                        'label' => $this->l('Log malware'),
                        'name' => 'LITE_MALWARE_SCAN_LOG',
                        'is_bool' => true,
                        'desc' => $this->proFeature . $this->l('Scan all your directories for malicious code and log it if something is found.'),
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
                        'disabled' => true,
                        'tab' => 'antiVirus',
                        'type' => 'text',
                        'col' => 6,
                        'desc' => $this->l('Whitelist false positives, caused by custom modules etc.') . $this->l('Separate files by comma (\',\')') . '.',
                        'name' => 'LITE_WHITELIST_MALWARE',
                        'label' => $this->l('Whitelist filter for malware'),
                        'hint' => $this->l('E.g.') . ' file.js,file.php',
                    ],
                    [
                        'disabled' => true,
                        'col' => 3,
                        'tab' => 'antiVirus',
                        'type' => 'text',
                        'prefix' => '<i class="icon-envelope-o"></i>',
                        'desc' => $this->proFeature . $this->l('Enter the e-mail which you would like to be notified at.'),
                        'name' => 'LITE_ANTI_VIRUS_EMAIL',
                        'label' => $this->l('E-mail'),
                        'hint' => $this->l('Need to be a valid e-mail address'),
                        'required' => true,
                    ],
                    [
                        'disabled' => true,
                        'tab' => 'antiVirus',
                        'type' => 'switch',
                        'col' => 6,
                        'label' => $this->l('Block file uploads'),
                        'name' => 'LITE_BLOCK_FILE_UPLOAD_BACK_OFFICE_ACTIVATE',
                        'is_bool' => true,
                        'desc' => $this->l('Block fileupload for specific files in back office. Add your custom list below.'),
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
                        'disabled' => true,
                        'tab' => 'antiVirus',
                        'type' => 'text',
                        'col' => 6,
                        'desc' => $this->proFeature . $this->l('List all file extensions that you want to block in back office.') . ' ' . $this->l('Separate files by comma (\',\')') . '.',
                        'name' => 'LITE_BLOCK_FILE_UPLOAD_BACK_OFFICE',
                        'label' => $this->l('Custom list of file-extensions'),
                        'hint' => $this->l('E.g.') . ' exe,com,bat',
                    ],
                    [
                        'tab' => 'protectContent',
                        'type' => 'select',
                        'label' => $this->l('Disable right click'),
                        'desc' => $this->l('Disable right click mouse event.'),
                        'name' => 'LITE_DISABLE_RIGHT_CLICK',
                        'options' => [
                            'query' => [
                                [
                                    'id_option' => '1',
                                    'name' => $this->l('No'),
                                ],
                                [
                                    'id_option' => '2',
                                    'name' => $this->l('Yes'),
                                ],
                                [
                                    'id_option' => '3',
                                    'name' => $this->l('Only on images'),
                                ],
                            ],
                            'id' => 'id_option',
                            'name' => 'name',
                        ],
                    ],
                    [
                        'disabled' => true,
                        'tab' => 'protectContent',
                        'type' => 'switch',
                        'label' => $this->l('Disable drag and drop'),
                        'name' => 'LITE_DISABLE_DRAG',
                        'is_bool' => true,
                        'desc' => $this->proFeature . $this->l('Disable drag and drop mouse event.'),
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
                        'disabled' => true,
                        'tab' => 'protectContent',
                        'type' => 'switch',
                        'label' => $this->l('Disable copy'),
                        'name' => 'LITE_DISABLE_COPY',
                        'is_bool' => true,
                        'desc' => $this->proFeature . $this->l('Disable copy (E.g. Ctrl + c / ⌘ + c).'),
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
                        'disabled' => true,
                        'tab' => 'protectContent',
                        'type' => 'switch',
                        'label' => $this->l('Disable cut'),
                        'name' => 'LITE_DISABLE_CUT',
                        'is_bool' => true,
                        'desc' => $this->proFeature . $this->l('Disable cut (E.g. Ctrl + x / ⌘ + x).'),
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
                        'disabled' => true,
                        'tab' => 'protectContent',
                        'type' => 'switch',
                        'label' => $this->l('Disable paste'),
                        'name' => 'LITE_DISABLE_PASTE',
                        'is_bool' => true,
                        'desc' => $this->proFeature . $this->l('Disable paste (E.g. Ctrl + v / ⌘ + v).'),
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
                        'disabled' => true,
                        'tab' => 'protectContent',
                        'type' => 'switch',
                        'label' => $this->l('Disable text selection'),
                        'name' => 'LITE_DISABLE_TEXT_SELECTION',
                        'is_bool' => true,
                        'desc' => $this->proFeature . $this->l('Disable text selection.'),
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
                        'disabled' => true,
                        'tab' => 'protectContent',
                        'col' => 6,
                        'type' => 'textbutton',
                        'label' => $this->l('Whitelist'),
                        'hint' => $this->l('E.g.') . ' 123.456.789,123.456.*,123.*,...',
                        'desc' => $this->proFeature . $this->l('You can list your own IP addresses if you want to bypass your rules above.') . '<br>' . $this->l('The module can handle IPv4, IPv6 addresses, as well as IP ranges, in CIDR formats') . ' (' . $this->l('like') . ' <code>::1/128</code> ' . $this->l('or') . ' <code>127.0.0.1/32</code>) ' . $this->l('and in pattern format') . ' (' . $this->l('like') . ' <code>::*:*</code> ' . $this->l('or') . ' <code>127.0.*.*</code>). ' . $this->l('Separate by comma (\',\').'),
                        'name' => 'LITE_WHITELIST_PROTECT_CONTENT',
                        'button' => [
                            'label' => '<i class="icon-plus"></i> ' . $this->l('Add my IP'),
                            'attributes' => [
                                'onclick' => '',
                            ],
                        ],
                    ],
                    [
                        'disabled' => true,
                        'col' => 5,
                        'tab' => 'firewall',
                        'type' => 'text',
                        'prefix' => '<i class="icon-key"></i>',
                        'desc' => $this->proFeature . $this->l('To get your own public key (site key) please click on the following link') . ': <a href="' . $linkGoogleApi . '" target="_blank" rel="noopener noreferrer">' . $linkGoogleApi . '</a>. ' . $this->l('You will have to register to get a key, but it\'s completely free.'),
                        'name' => 'LITE_FIREWALL_RECAPCHA_SITE_KEY',
                        'label' => $this->l('Site key (reCAPTCHA v2)'),
                        'required' => true,
                    ],
                    [
                        'disabled' => true,
                        'col' => 5,
                        'tab' => 'firewall',
                        'type' => 'text',
                        'prefix' => '<i class="icon-key"></i>',
                        'desc' => $this->proFeature . $this->l('To get your own private key (secret key) please click on the following link') . ': <a href="' . $linkGoogleApi . '" target="_blank" rel="noopener noreferrer">' . $linkGoogleApi . '</a>. ' . $this->l('You will have to register to get a key, but it\'s completely free.'),
                        'name' => 'LITE_FIREWALL_RECAPCHA_SECRET',
                        'label' => $this->l('Secret key (reCAPTCHA v2)'),
                        'required' => true,
                    ],
                    [
                        'disabled' => true,
                        'tab' => 'firewall',
                        'type' => 'switch',
                        'col' => 6,
                        'label' => $this->l('Activate anti-flood'),
                        'name' => 'LITE_ANTI_FLOOD',
                        'is_bool' => true,
                        'desc' => $this->proFeature . $this->l('Anti-flood script that does not need cookies. This script is great for preventing most DDoS attacks and automatic multiple requests.'),
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
                        'disabled' => true,
                        'col' => 2,
                        'tab' => 'firewall',
                        'type' => 'text',
                        'suffix' => $this->l('requests'),
                        'prefix' => '<i class="icon-repeat"></i>',
                        'desc' => $this->proFeature . $this->l('Number of allowed page requests for the user.'),
                        'name' => 'LITE_ANTI_MAX_REQUESTS',
                        'label' => $this->l('Max requests'),
                        'hint' => $this->l('Must be an integer'),
                        'required' => true,
                    ],
                    [
                        'disabled' => true,
                        'col' => 2,
                        'tab' => 'firewall',
                        'type' => 'text',
                        'suffix' => $this->l('seconds'),
                        'prefix' => '<i class="icon-clock-o"></i>',
                        'desc' => $this->proFeature . $this->l('Time interval to start counting page requests.'),
                        'name' => 'LITE_ANTI_REQ_TIMEOUT',
                        'label' => $this->l('Request timeout'),
                        'hint' => $this->l('Must be an integer'),
                        'required' => true,
                    ],
                    [
                        'disabled' => true,
                        'col' => 2,
                        'tab' => 'firewall',
                        'type' => 'text',
                        'suffix' => $this->l('seconds'),
                        'prefix' => '<i class="icon-clock-o"></i>',
                        'desc' => $this->proFeature . $this->l('Time to punish the user who has exceeded in doing requests.'),
                        'name' => 'LITE_ANTI_BAN_TIME',
                        'label' => $this->l('Ban time'),
                        'hint' => $this->l('Must be an integer'),
                        'required' => true,
                    ],
                    [
                        'disabled' => true,
                        'col' => 5,
                        'tab' => 'firewall',
                        'type' => 'text',
                        'prefix' => '<i class="icon-key"></i>',
                        'desc' => $this->proFeature . $this->l('To get your own honeypot key please click on the following link') . ': <a href="' . $linkHoneypotApi . '" target="_blank" rel="noopener noreferrer">' . $linkHoneypotApi . '</a>. ' . $this->l('You will have to register to get a key, but it\'s completely free.'),
                        'name' => 'LITE_HONEYPOT_API',
                        'label' => 'Honeypot API',
                        'hint' => $this->l('Access keys are 12-alpha characters (no numbers). They are lower-case.'),
                        'required' => true,
                    ],
                    [
                        'disabled' => true,
                        'tab' => 'firewall',
                        'type' => 'switch',
                        'col' => 6,
                        'label' => $this->l('Activate bot check'),
                        'name' => 'LITE_FIREWALL_CHECK_BOT',
                        'is_bool' => true,
                        'desc' => $this->proFeature . $this->l('Detect if the client is listed in honeypot project or is connected though TOR network IPv4/IPv6. If positive, the client will need to solve a reCAPCHA to get whitelisted.'),

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
                        'disabled' => true,
                        'tab' => 'firewall',
                        'type' => 'switch',
                        'col' => 6,
                        'label' => $this->l('Activate anti-SQL injection'),
                        'name' => 'LITE_FIREWALL_SQL_CHECK',
                        'is_bool' => true,
                        'desc' => $this->proFeature . $this->l('SQL injection is a web security vulnerability that allows an attacker to interfere with the queries that an application makes to its database.') . ' ' . $this->l('If the request looks like an attack, the client will need to solve a reCAPCHA before the request can proceed.'),
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
                        'disabled' => true,
                        'tab' => 'firewall',
                        'type' => 'switch',
                        'col' => 6,
                        'label' => $this->l('Activate anti-XXS injection'),
                        'name' => 'LITE_FIREWALL_XXS_CHECK',
                        'is_bool' => true,
                        'desc' => $this->proFeature . $this->l('XSS (Cross-Site Scripting) injection is a web security vulnerability that allows an attacker to inject code (basically client-side scripting) to the remote server.') . ' ' . $this->l('If the request looks like an attack, the client will need to solve a reCAPCHA before the request can proceed.'),
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
                        'disabled' => true,
                        'tab' => 'firewall',
                        'type' => 'switch',
                        'col' => 6,
                        'label' => $this->l('Activate anti-SHELL injection'),
                        'name' => 'LITE_FIREWALL_SHELL_CHECK',
                        'is_bool' => true,
                        'desc' => $this->proFeature . $this->l('SHELL injection is a web security vulnerability that allows an attacker to inject code to the remote server.') . ' ' . $this->l('If the request looks like an attack, the client will need to solve a reCAPCHA before the request can proceed.'),
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
                        'disabled' => true,
                        'tab' => 'firewall',
                        'type' => 'switch',
                        'col' => 6,
                        'label' => $this->l('Activate anti-HTML injection'),
                        'name' => 'LITE_FIREWALL_HTML_CHECK',
                        'is_bool' => true,
                        'desc' => $this->proFeature . $this->l('HTML injection is a web security vulnerability that allows an attacker to change the website\'s design or any information, that is displayed to the user.') . ' ' . $this->l('If the request looks like an attack, the client will need to solve a reCAPCHA before the request can proceed.'),
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
                        'disabled' => true,
                        'tab' => 'firewall',
                        'type' => 'switch',
                        'col' => 6,
                        'label' => $this->l('Activate anti-XST injection'),
                        'name' => 'LITE_FIREWALL_XST_CHECK',
                        'is_bool' => true,
                        'desc' => $this->proFeature . $this->l('Cross-Site Tracing (XST) is a network security vulnerability exploiting the HTTP TRACE method. Enable this option to block HTTP TRACK and HTTP TRACE requests.'),
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
                        'disabled' => true,
                        'tab' => 'firewall',
                        'type' => 'switch',
                        'col' => 6,
                        'label' => $this->l('Block too long HTTP requests'),
                        'name' => 'LITE_FIREWALL_CHECK_REQUEST',
                        'is_bool' => true,
                        'desc' => $this->proFeature . $this->l('Block the request if the HTTP request is more than 2500 characters.'),
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
                        'disabled' => true,
                        'tab' => 'firewall',
                        'type' => 'switch',
                        'col' => 6,
                        'label' => $this->l('Block user agents with too long names'),
                        'name' => 'LITE_FIREWALL_CHECK_USERAGENT',
                        'is_bool' => true,
                        'desc' => $this->proFeature . $this->l('Block the request if the user agent name is more than 472 characters.'),
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
                        'disabled' => true,
                        'tab' => 'firewall',
                        'type' => 'switch',
                        'col' => 6,
                        'label' => $this->l('Block old HTTP protocols'),
                        'name' => 'LITE_FIREWALL_OLD_PROTOCOL',
                        'is_bool' => true,
                        'desc' => $this->proFeature . $this->l('Block HTTP/0.9 and HTTP/1.0 requests. Real humans will connect with HTTP/1.1, HTTP/2.0 or HTTP/3.0.'),
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
                        'disabled' => true,
                        'tab' => 'firewall',
                        'type' => 'switch',
                        'col' => 6,
                        'label' => $this->l('Block file-upload'),
                        'name' => 'LITE_BLOCK_FILE_UPLOAD',
                        'is_bool' => true,
                        'desc' => $this->proFeature . $this->l('Block file uploads in front office. Don\'t enable this if you use contact form.'),
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
                        'disabled' => true,
                        'tab' => 'firewall',
                        'type' => 'switch',
                        'col' => 6,
                        'label' => $this->l('Activate log'),
                        'name' => 'LITE_FIREWALL_LOG',
                        'is_bool' => true,
                        'desc' => $this->proFeature . $this->l('Record hacking attempts into a log file.'),
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
                        'disabled' => true,
                        'tab' => 'tfa',
                        'type' => 'switch',
                        'col' => 6,
                        'label' => $this->l('Activate Two-Factor Authentication'),
                        'name' => 'LITE_TWO_FACTOR_AUTH',
                        'is_bool' => true,
                        'desc' => $this->proFeature . $this->l('Download') . ' <strong> ' . $this->l('Google Authenticator') . '</strong> ' . $this->l('app on your phone. Open the app and scan the QR code. Insert the code you see on your phone in the code input field below to verify that everything is working. Then save settings.') . '<br><br>' . $this->l('Your key') . ' (' . $this->l('for manual input') . '):<br><strong>' . \chunk_split($this->getSecret(), 4, ' ') . '</strong><br><br>QR-code:<br><img src="' . $tfa->getQRCodeImageAsDataUri('Admin', $this->getSecret()) . '">',
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
                        'disabled' => true,
                        'col' => 2,
                        'tab' => 'tfa',
                        'type' => 'text',
                        'prefix' => '<i class="icon-key"></i>',
                        'desc' => $this->proFeature . $this->l('To validate that everything is correct, you must enter your code from your app before you save settings.'),
                        'name' => 'LITE_TWO_FACTOR_AUTH_CODE',
                        'label' => $this->l('Code'),
                        'hint' => $this->l('Must be 6 digitals'),
                        'required' => true,
                    ],
                    [
                        'disabled' => true,
                        'tab' => 'tfa',
                        'type' => 'textbutton',
                        'col' => 6,
                        'desc' => $this->proFeature . $this->l('You can list your own IP addresses if you want to skip the Two-Factor Authentication when you are on a specific network.') . '<br>' . $this->l('The module can handle IPv4, IPv6 addresses, as well as IP ranges, in CIDR formats') . $this->l('like') . ' <code>::1/128</code> ' . $this->l('or') . ' <code>127.0.0.1/32</code>) ' . $this->l('and in pattern format') . ' (' . $this->l('like') . ' <code>::*:*</code> ' . $this->l('or') . ' <code>127.0.*.*</code>). ' . $this->l('Separate by comma (\',\').'),
                        'name' => 'LITE_TWO_FACTOR_AUTH_WHITELIST',
                        'button' => [
                            'label' => '<i class="icon-plus"></i> ' . $this->l('Add my IP'),
                            'attributes' => [
                                'onclick' => '',
                            ],
                        ],
                        'label' => $this->l('Whitelist IP addresses'),
                        'hint' => $this->l('E.g.') . ' 123.456.789,123.456.*,123.*,...',
                    ],
                ],
                'submit' => [
                    'title' => $this->l('Save'),
                ],
            ],
        ];
    }

    /**
     * Configure form values.
     */
    protected function getConfigFormValues()
    {
        return [
            'LITE_CLICK_JACKING' => Configuration::get('LITE_CLICK_JACKING'),
            'LITE_X_XSS_PPROTECTION' => Configuration::get('LITE_X_XSS_PPROTECTION'),
            'LITE_X_CONTENT_TYPE_OPTIONS' => Configuration::get('LITE_X_CONTENT_TYPE_OPTIONS'),
            'LITE_STRICT_TRANSPORT_SECURITY' => Configuration::get('LITE_STRICT_TRANSPORT_SECURITY'),
            'LITE_HSTS_SETTINGS_0' => Configuration::get('LITE_HSTS_SETTINGS_0'),
            'LITE_HSTS_SETTINGS_1' => Configuration::get('LITE_HSTS_SETTINGS_1'),
            'LITE_EXPECT_CT' => Configuration::get('LITE_EXPECT_CT'),
            'LITE_REFFERER_POLICY' => Configuration::get('LITE_REFFERER_POLICY'),
            'LITE_HTPASSWD' => Configuration::get('LITE_HTPASSWD'),
            'LITE_HTPASSWD_USER' => Configuration::get('LITE_HTPASSWD_USER'),
            'LITE_HTPASSWD_PASS' => Configuration::get('LITE_HTPASSWD_PASS'),
            'LITE_BAN_IP' => Configuration::get('LITE_BAN_IP'),
            'LITE_BAN_IP_ACTIVATE' => Configuration::get('LITE_BAN_IP_ACTIVATE'),
            'LITE_FAIL2BAN' => Configuration::get('LITE_FAIL2BAN'),
            'LITE_FAIL2BAN_EMAIL' => Configuration::get('LITE_FAIL2BAN_EMAIL'),
            'LITE_FAIL2BAN_LOG' => Configuration::get('LITE_FAIL2BAN_LOG'),
            'LITE_BAN_TIME' => (int) Configuration::get('LITE_BAN_TIME'),
            'LITE_MAX_RETRY' => (int) Configuration::get('LITE_MAX_RETRY'),
            'LITE_FIND_TIME' => (int) Configuration::get('LITE_FIND_TIME'),
            'LITE_SEND_MAIL' => Configuration::get('LITE_SEND_MAIL'),
            'LITE_SEND_MAIL_LOGIN' => Configuration::get('LITE_SEND_MAIL_LOGIN'),
            'LITE_WHITELIST_IPS' => Configuration::get('LITE_WHITELIST_IPS'),
            'LITE_FILE_CHANGES_EMAIL' => Configuration::get('LITE_FILE_CHANGES_EMAIL'),
            'LITE_FILE_CHANGES_LOG' => Configuration::get('LITE_FILE_CHANGES_LOG'),
            'LITE_FILE_CHANGES_WHITELIST' => Configuration::get('LITE_FILE_CHANGES_WHITELIST'),
            'LITE_MALWARE_SCAN_EMAIL' => Configuration::get('LITE_MALWARE_SCAN_EMAIL'),
            'LITE_MALWARE_SCAN_LOG' => Configuration::get('LITE_MALWARE_SCAN_LOG'),
            'LITE_WHITELIST_MALWARE' => Configuration::get('LITE_WHITELIST_MALWARE'),
            'LITE_BLOCK_FILE_UPLOAD_BACK_OFFICE_ACTIVATE' => Configuration::get('LITE_BLOCK_FILE_UPLOAD_BACK_OFFICE_ACTIVATE'),
            'LITE_BLOCK_FILE_UPLOAD_BACK_OFFICE' => Configuration::get('LITE_BLOCK_FILE_UPLOAD_BACK_OFFICE'),
            'LITE_ANTI_VIRUS_EMAIL' => Configuration::get('LITE_ANTI_VIRUS_EMAIL'),
            'LITE_DISABLE_RIGHT_CLICK' => Configuration::get('LITE_DISABLE_RIGHT_CLICK'),
            'LITE_DISABLE_DRAG' => Configuration::get('LITE_DISABLE_DRAG'),
            'LITE_DISABLE_COPY' => Configuration::get('LITE_DISABLE_COPY'),
            'LITE_DISABLE_CUT' => Configuration::get('LITE_DISABLE_CUT'),
            'LITE_DISABLE_PASTE' => Configuration::get('LITE_DISABLE_PASTE'),
            'LITE_DISABLE_TEXT_SELECTION' => Configuration::get('LITE_DISABLE_TEXT_SELECTION'),
            'LITE_ADMIN_DIRECTORY' => Configuration::get('LITE_ADMIN_DIRECTORY'),
            'LITE_ADMIN_DIRECTORY_NAME' => Configuration::get('LITE_ADMIN_DIRECTORY_NAME'),
            'LITE_BACKUP_DB_TOKEN' => Configuration::get('LITE_BACKUP_DB_TOKEN'),
            'LITE_ANTI_FLOOD' => Configuration::get('LITE_ANTI_FLOOD'),
            'LITE_ANTI_MAX_REQUESTS' => (int) Configuration::get('LITE_ANTI_MAX_REQUESTS'),
            'LITE_ANTI_REQ_TIMEOUT' => (int) Configuration::get('LITE_ANTI_REQ_TIMEOUT'),
            'LITE_ANTI_BAN_TIME' => (int) Configuration::get('LITE_ANTI_BAN_TIME'),
            'LITE_FIREWALL_RECAPCHA_SECRET' => Configuration::get('LITE_FIREWALL_RECAPCHA_SECRET'),
            'LITE_FIREWALL_RECAPCHA_SITE_KEY' => Configuration::get('LITE_FIREWALL_RECAPCHA_SITE_KEY'),
            'LITE_HONEYPOT_API' => Configuration::get('LITE_HONEYPOT_API'),
            'LITE_FIREWALL_CHECK_BOT' => Configuration::get('LITE_FIREWALL_CHECK_BOT'),
            'LITE_FIREWALL_SQL_CHECK' => Configuration::get('LITE_FIREWALL_SQL_CHECK'),
            'LITE_FIREWALL_XXS_CHECK' => Configuration::get('LITE_FIREWALL_XXS_CHECK'),
            'LITE_FIREWALL_SHELL_CHECK' => Configuration::get('LITE_FIREWALL_SHELL_CHECK'),
            'LITE_FIREWALL_XST_CHECK' => Configuration::get('LITE_FIREWALL_XST_CHECK'),
            'LITE_FIREWALL_HTML_CHECK' => Configuration::get('LITE_FIREWALL_HTML_CHECK'),
            'LITE_FIREWALL_CHECK_REQUEST' => Configuration::get('LITE_FIREWALL_CHECK_REQUEST'),
            'LITE_FIREWALL_CHECK_USERAGENT' => Configuration::get('LITE_FIREWALL_CHECK_USERAGENT'),
            'LITE_FIREWALL_OLD_PROTOCOL' => Configuration::get('LITE_FIREWALL_OLD_PROTOCOL'),
            'LITE_BLOCK_FILE_UPLOAD' => Configuration::get('LITE_BLOCK_FILE_UPLOAD'),
            'LITE_FIREWALL_LOG' => Configuration::get('LITE_FIREWALL_LOG'),
            'LITE_PASSWORD_GENERATOR' => Configuration::get('LITE_PASSWORD_GENERATOR'),
            'LITE_BACKUP_DB' => Configuration::get('LITE_BACKUP_DB'),
            'LITE_BACKUP_DB_DROPBOX' => Configuration::get('LITE_BACKUP_DB_DROPBOX'),
            'LITE_BACKUP_DB_TOKEN' => Configuration::get('LITE_BACKUP_DB_TOKEN'),
            'LITE_BACKUP_DB_SAVED' => (int) Configuration::get('LITE_BACKUP_DB_SAVED'),
            'LITE_BACKUP_FILE_SAVED' => (int) Configuration::get('LITE_BACKUP_FILE_SAVED'),
            'LITE_BACKUP_FILE' => Configuration::get('LITE_BACKUP_FILE'),
            'LITE_BACKUP_FILE_DROPBOX' => Configuration::get('LITE_BACKUP_FILE_DROPBOX'),
            'LITE_BACKUP_COMPRESSION' => Configuration::get('LITE_BACKUP_COMPRESSION'),
            'LITE_TWO_FACTOR_AUTH' => Configuration::get('LITE_TWO_FACTOR_AUTH'),
            'LITE_TWO_FACTOR_AUTH_CODE' => Configuration::get('LITE_TWO_FACTOR_AUTH_CODE'),
            'LITE_TWO_FACTOR_AUTH_WHITELIST' => Configuration::get('LITE_TWO_FACTOR_AUTH_WHITELIST'),
            'LITE_FAKE_ACCOUNTS' => Configuration::get('LITE_FAKE_ACCOUNTS'),
            'LITE_WHITELIST_PROTECT_CONTENT' => Configuration::get('LITE_WHITELIST_PROTECT_CONTENT'),
            'LITE_BLOCK_USER_AGENT_ACTIVATE' => Configuration::get('LITE_BLOCK_USER_AGENT_ACTIVATE'),
            'LITE_BLOCK_USER_AGENT' => Configuration::get('LITE_BLOCK_USER_AGENT'),
            'LITE_BLOCK_TOR' => Configuration::get('LITE_BLOCK_TOR'),
            'LITE_DISABLE_CONTACT_FORM' => Configuration::get('LITE_DISABLE_CONTACT_FORM'),
        ];
    }

    /**
     * Post configure form values.
     */
    protected function postProcess()
    {
        $form_values = $this->getConfigFormValues();

        foreach (\array_keys($form_values) as $key) {
            Configuration::updateValue($key, Tools::getValue($key));
        }
    }

    private function checkCVE201819355()
    {
        $check = '<a href="https://nvd.nist.gov/vuln/detail/CVE-2018-19355" target="_blank" rel="noopener noreferrer">CVE-2018-19355</a>';

        $status = \file_exists(_PS_MODULE_DIR_ . 'orderfiles/upload.php');

        $fix = $this->l('Update') . ' "orderfiles" ' . $this->l('module to latest version.');

        return [
            $check,
            $status,
            $fix,
        ];
    }

    //start

    /**
     * Check CVE-2020-5264.
     *
     * @return array
     */
    private function checkCve20205264()
    {
        $check = '<a href="https://nvd.nist.gov/vuln/detail/CVE-2020-5264" target="_blank" rel="noopener noreferrer">CVE-2020-5264</a>';

        $status = false;
        if (Tools::version_compare(_PS_VERSION_, '1.7.0.0', '>=') && Tools::version_compare(_PS_VERSION_, '1.7.6.5', '<')) {
            $status = true;
        }

        $fix = $this->l('Update PrestaShop to latest version.');

        return [
            $check,
            $status,
            $fix,
        ];
    }

    /**
     * Check CVE-2020-5265.
     *
     * @return array
     */
    private function checkCve20205265()
    {
        $check = '<a href="https://nvd.nist.gov/vuln/detail/CVE-2020-5265" target="_blank" rel="noopener noreferrer">CVE-2020-5265</a>';

        $status = false;
        if (Tools::version_compare(_PS_VERSION_, '1.7.6.1', '>=') && Tools::version_compare(_PS_VERSION_, '1.7.6.5', '<')) {
            $status = true;
        }

        $fix = $this->l('Update PrestaShop to latest version.');

        return [
            $check,
            $status,
            $fix,
        ];
    }

    /**
     * Check CVE-2020-5269.
     *
     * @return array
     */
    private function checkCve20205269()
    {
        $check = '<a href="https://nvd.nist.gov/vuln/detail/CVE-2020-5269" target="_blank" rel="noopener noreferrer">CVE-2020-5269</a>';

        $status = false;
        if (Tools::version_compare(_PS_VERSION_, '1.7.6.1', '>=') && Tools::version_compare(_PS_VERSION_, '1.7.6.5', '<')) {
            $status = true;
        }

        $fix = $this->l('Update PrestaShop to latest version.');

        return [
            $check,
            $status,
            $fix,
        ];
    }

    /**
     * Check CVE-2020-5270.
     *
     * @return array
     */
    private function checkCve20205270()
    {
        $check = '<a href="https://nvd.nist.gov/vuln/detail/CVE-2020-5270" target="_blank" rel="noopener noreferrer">CVE-2020-5270</a>';

        $status = false;
        if (Tools::version_compare(_PS_VERSION_, '1.7.6.0', '>=') && Tools::version_compare(_PS_VERSION_, '1.7.6.5', '<')) {
            $status = true;
        }

        $fix = $this->l('Update PrestaShop to latest version.');

        return [
            $check,
            $status,
            $fix,
        ];
    }

    /**
     * Check CVE-2020-5270.
     *
     * @return array
     */
    private function checkCve20205272()
    {
        $check = '<a href="https://nvd.nist.gov/vuln/detail/CVE-2020-5272" target="_blank" rel="noopener noreferrer">CVE-2020-5272</a>';

        $status = false;
        if (Tools::version_compare(_PS_VERSION_, '1.5.5.0', '>=') && Tools::version_compare(_PS_VERSION_, '1.7.6.5', '<')) {
            $status = true;
        }

        $fix = $this->l('Update PrestaShop to latest version.');

        return [
            $check,
            $status,
            $fix,
        ];
    }

    /**
     * Check CVE-2020-5270.
     *
     * @return array
     */
    private function checkCve20205279()
    {
        $check = '<a href="https://nvd.nist.gov/vuln/detail/CVE-2020-5279" target="_blank" rel="noopener noreferrer">CVE-2020-5279</a>';

        $status = false;
        if (Tools::version_compare(_PS_VERSION_, '1.5.0.0', '>=') && Tools::version_compare(_PS_VERSION_, '1.7.6.5', '<')) {
            $status = true;
        }

        $fix = $this->l('Update PrestaShop to latest version.');

        return [
            $check,
            $status,
            $fix,
        ];
    }

    /**
     * Check CVE-2020-5270.
     *
     * @return array
     */
    private function checkCve20205276()
    {
        $check = '<a href="https://nvd.nist.gov/vuln/detail/CVE-2020-5276" target="_blank" rel="noopener noreferrer">CVE-2020-5276</a>';

        $status = false;
        if (Tools::version_compare(_PS_VERSION_, '1.7.1.0', '>=') && Tools::version_compare(_PS_VERSION_, '1.7.6.5', '<')) {
            $status = true;
        }

        $fix = $this->l('Update PrestaShop to latest version.');

        return [
            $check,
            $status,
            $fix,
        ];
    }

    /**
     * Check CVE-2020-5270.
     *
     * @return array
     */
    private function checkCve20205278()
    {
        $check = '<a href="https://nvd.nist.gov/vuln/detail/CVE-2020-5278" target="_blank" rel="noopener noreferrer">CVE-2020-5278</a>';

        $status = false;
        if (Tools::version_compare(_PS_VERSION_, '1.5.4.0', '>=') && Tools::version_compare(_PS_VERSION_, '1.7.6.5', '<')) {
            $status = true;
        }

        $fix = $this->l('Update PrestaShop to latest version.');

        return [
            $check,
            $status,
            $fix,
        ];
    }

    /**
     * Check CVE-2020-5286.
     *
     * @return array
     */
    private function checkCve20205286()
    {
        $check = '<a href="https://nvd.nist.gov/vuln/detail/CVE-2020-5286" target="_blank" rel="noopener noreferrer">CVE-2020-5286</a>';

        $status = false;
        if (Tools::version_compare(_PS_VERSION_, '1.7.4.0', '>=') && Tools::version_compare(_PS_VERSION_, '1.7.6.5', '<')) {
            $status = true;
        }

        $fix = $this->l('Update PrestaShop to latest version.');

        return [
            $check,
            $status,
            $fix,
        ];
    }

    /**
     * Check CVE-2020-5270.
     *
     * @return array
     */
    private function checkCve20205285()
    {
        $check = '<a href="https://nvd.nist.gov/vuln/detail/CVE-2020-5285" target="_blank" rel="noopener noreferrer">CVE-2020-5285</a>';

        $status = false;
        if (Tools::version_compare(_PS_VERSION_, '1.7.6.0', '>=') && Tools::version_compare(_PS_VERSION_, '1.7.6.5', '<')) {
            $status = true;
        }

        $fix = $this->l('Update PrestaShop to latest version.');

        return [
            $check,
            $status,
            $fix,
        ];
    }

    /**
     * Check CVE-2020-5287.
     *
     * @return array
     */
    private function checkCve20205287()
    {
        $check = '<a href="https://nvd.nist.gov/vuln/detail/CVE-2020-5287" target="_blank" rel="noopener noreferrer">CVE-2020-5287</a>';

        $status = false;
        if (Tools::version_compare(_PS_VERSION_, '1.5.5.0', '>=') && Tools::version_compare(_PS_VERSION_, '1.7.6.5', '<')) {
            $status = true;
        }

        $fix = $this->l('Update PrestaShop to latest version.');

        return [
            $check,
            $status,
            $fix,
        ];
    }

    /**
     * Check CVE-2020-5288.
     *
     * @return array
     */
    private function checkCve20205288()
    {
        $check = '<a href="https://nvd.nist.gov/vuln/detail/CVE-2020-5288" target="_blank" rel="noopener noreferrer">CVE-2020-5288</a>';

        $status = false;
        if (Tools::version_compare(_PS_VERSION_, '1.7.0.0', '>=') && Tools::version_compare(_PS_VERSION_, '1.7.6.5', '<')) {
            $status = true;
        }

        $fix = $this->l('Update PrestaShop to latest version.');

        return [
            $check,
            $status,
            $fix,
        ];
    }

    /**
     * Check CVE-2020-5293.
     *
     * @return array
     */
    private function checkCve20205293()
    {
        $check = '<a href="https://nvd.nist.gov/vuln/detail/CVE-2020-5293" target="_blank" rel="noopener noreferrer">CVE-2020-5293</a>';

        $status = false;
        if (Tools::version_compare(_PS_VERSION_, '1.7.0.0', '>=') && Tools::version_compare(_PS_VERSION_, '1.7.6.5', '<')) {
            $status = true;
        }

        $fix = $this->l('Update PrestaShop to latest version.');

        return [
            $check,
            $status,
            $fix,
        ];
    }

    /**
     * Check CVE-2020-5293.
     *
     * @return array
     */
    private function checkCve20205271()
    {
        $check = '<a href="https://nvd.nist.gov/vuln/detail/CVE-2020-5271" target="_blank" rel="noopener noreferrer">CVE-2020-5271</a>';

        $status = false;
        if (Tools::version_compare(_PS_VERSION_, '1.6.0.0', '>=') && Tools::version_compare(_PS_VERSION_, '1.7.6.5', '<')) {
            $status = true;
        }

        $fix = $this->l('Update PrestaShop to latest version.');

        return [
            $check,
            $status,
            $fix,
        ];
    }

    private function analyzeSystem()
    {
        $helper = new HelperList();
        $helper->module = $this;
        $helper->title = $this->l('Analyze your system for known security vulnerabilities and recommend options for increased protection');
        $helper->simple_header = false;
        $helper->title_icon = 'icon-list';
        $helper->shopLinkType = '';
        $helper->no_link = true;
        $helper->show_toolbar = true;
        $helper->simple_header = false;
        $helper->currentIndex = $this->context->link->getAdminLink('AdminModules', false) . '&configure=securitylite';
        $helper->token = \Tools::getAdminTokenLite('AdminModules');
        $check = '<i class="icon icon-check" style="color: green"></i>';
        $vulnerable = '<i class="icon icon-times" style="color: red"></i>';
        $good = '--';
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

        $checkGrids = [
            $this->checkCve20205293(),
            $this->checkCve20205288(),
            $this->checkCve20205287(),
            $this->checkCve20205286(),
            $this->checkCve20205285(),
            $this->checkCve20205279(),
            $this->checkCve20205278(),
            $this->checkCve20205276(),
            $this->checkCve20205272(),
            $this->checkCve20205271(),
            $this->checkCve20205270(),
            $this->checkCve20205269(),
            $this->checkCve20205265(),
            $this->checkCve20205264(),
            $this->checkCve20205250(),
            $this->checkCve201913461(),
            $this->checkCve201911876(),
            $this->checkCve20188824(),
            $this->checkCve20187491(),
            $this->checkCve201819355(),
            $this->checkCve201819126(),
            $this->checkCve201813784(),
            $this->checkCve20179841(),
            $this->checkCve20151175(),
            $this->checkPhpVersion(),
            $this->checkSslEnabled(),
            $this->checkSslEnabledEverywhere(),
            $this->checkPrestashopToken(),
            $this->checkModSecurity(),
            $this->checkAdminDirectoryName(),
            $this->checkPsTablePrefix(),
            $this->checkPrestashopDevMode(),
        ];
        $result = [];
        foreach ($checkGrids as $checkGrid) {
            $result[] = [
                'check' => $checkGrid[0],
                'status' => $checkGrid[1] ? $vulnerable : $check,
                'fix' => $checkGrid[1] ? $checkGrid[2] : $good,
            ];
        }

        return $helper->generateList($result, $fields_list);
    }

    private function analyzePhpIni()
    {
        $helper = new HelperList();
        $helper->module = $this;
        $helper->title = $this->l('Analyze your php.ini configuration');
        $helper->shopLinkType = '';
        $helper->simple_header = false;
        $helper->title_icon = 'icon-list';
        $helper->no_link = true;
        $helper->show_toolbar = true;
        $helper->simple_header = false;
        $helper->currentIndex = $this->context->link->getAdminLink('AdminModules', false) . '&configure=securitylite';
        $helper->token = \Tools::getAdminTokenLite('AdminModules');
        $fields_list = [
            'key' => [
                'title' => '<strong>' . $this->l('Setting') . '</strong>',
                'search' => false,
                'float' => true,
            ],
            'current' => [
                'title' => '<strong>' . $this->l('Current value') . '</strong>',
                'search' => false,
                'float' => true,
            ],
            'recommended' => [
                'title' => '<strong>' . $this->l('Recommended value') . '</strong>',
                'search' => false,
                'float' => true,
            ],
            'status' => [
                'title' => '<strong>' . $this->l('Status') . '</strong>',
                'search' => false,
                'float' => true,
            ],
            'desc' => [
                'title' => '<strong>' . $this->l('Description') . '</strong>',
                'search' => false,
                'float' => true,
            ],
        ];
        $checkGrids = [
            $this->checkSessionUseCookies(),
            $this->checkSessionUseOnlyCookies(),
            $this->checkSessionCookieHttponly(),
            $this->checkAessionHashFunction(),
            $this->checkPhpUseTransSid(),
            $this->checkCookieSecure(),
            $this->checkUseScrickMode(),
            $this->checkCookieLifetime(),
            $this->checkLazyWrite(),
            $this->checkSidLength(),
            $this->checkSessionGcDivisor(),
            $this->checkSidBitsPerCharacter(),
            $this->checkUrlFopen(),
            $this->checkUrlInclude(),
            $this->checkDisplayErrors(),
            $this->checkLogErrors(),
            $this->checkErrorReporting(),
            $this->checkDisplayStartupErrors(),
            $this->checkExposePhp(),
            $this->checkRegisterGlobals(),
            $this->checkRegisterArgcArgv(),
            $this->checkShortOpenTag(),
            $this->checkXdebugDefaultEnable(),
            $this->checkXdebugRemoteEnable(),
            $this->checkFileUploads(),
            $this->checkUploadMaxFileSize(),
            $this->checkPostMaxSize(),
            $this->checkMaxInputVars(),
            $this->checkMaxInputTime(),
            $this->checkMemoryLimit(),
            $this->checkMaxExecutionTime(),
            $this->checkDefaultCharset(),
        ];
        $result = [];
        foreach ($checkGrids as $checkGrid) {
            $result[] = [
                'key' => $checkGrid[0],
                'current' => $checkGrid[1],
                'recommended' => $this->proFeature,
                'status' => $this->proFeature,
                'desc' => $this->proFeature,
            ];
        }

        return $helper->generateList($result, $fields_list);
    }

    private function getBaseURL()
    {
        if (Tools::version_compare(_PS_VERSION_, '1.7', '>=')) {
            return $this->context->link->getBaseLink();
        }
        if (true === (bool) Configuration::get('PS_SSL_ENABLED')) {
            return \Context::getContext()->shop->getBaseURL(true);
        }

        return \Context::getContext()->shop->getBaseURL(false);
    }

    private function getTwoFactorAuthDB($column)
    {
        $sql = new DbQuery();
        $sql->from('securitylite_tfa');
        $sql->select($column);

        return Db::getInstance()->getValue($sql);
    }

    private function updateTwoFactorAuthDB($column, $value)
    {
        $query = 'UPDATE `' . _DB_PREFIX_ . 'securitylite_tfa` SET ' . $column . '="' . $value . '"';

        return Db::getInstance()->Execute($query);
    }

    private function isInWhitelistForGeolocation($userIp)
    {
        $ips = \explode(';', Configuration::get('PS_GEOLOCATION_WHITELIST'));
        if (\is_array($ips) && \count($ips)) {
            foreach ($ips as $ip) {
                if (!empty($ip) && 0 === \mb_strpos($userIp, $ip)) {
                    return true;
                }
            }
        }

        return false;
    }

    private function validateIps($field)
    {
        if (false === (bool) Configuration::get($field)) {
            return;
        }

        $input = \preg_replace('/\s+/', '', Configuration::get($field));
        $input = \preg_replace('/,,+/', ',', $input);
        if (',' === \Tools::substr($input, -1)) {
            $input = \Tools::substr($input, 0, -1);
        }
        $input = \implode(',', Tools::arrayUnique(\explode(',', $input)));

        $lists = \explode(',', $input);
        $output = [];
        foreach ($lists as &$list) {
            if (!empty(\IPLib\Factory::rangeFromString($list))) {
                if ('LITE_BAN_IP' === $field) {
                    if (false === $this->isInWhitelistForGeolocation($list)) {
                        $output[] = $list;
                    }
                } else {
                    $output[] = $list;
                }
            }
        }

        Configuration::updateValue($field, \implode(',', $output));
    }

    private function validateCommaSeperatedString($field)
    {
        if (false === (bool) Configuration::get($field)) {
            return;
        }

        $input = \preg_replace('/\s+/', '', Configuration::get($field));
        $input = \preg_replace('/,,+/', ',', $input);
        if (',' === \Tools::substr($input, -1)) {
            $input = \Tools::substr($input, 0, -1);
        }
        if (',' === \Tools::substr($input, 0, 1)) {
            $input = \Tools::substr($input, 1);
        }
        $input = \implode(',', Tools::arrayUnique(\explode(',', $input)));

        Configuration::updateValue($field, $input);
    }

    private function checkCVE201913461()
    {
        $check = '<a href="https://nvd.nist.gov/vuln/detail/CVE-2019-13461" target="_blank" rel="noopener noreferrer">CVE-2019-13461</a>';
        $status = Tools::version_compare(_PS_VERSION_, '1.7.6.0', '<');
        $fix = $this->l('Update PrestaShop to latest version.');

        return [
            $check,
            $status,
            $fix,
        ];
    }

    private function checkCVE201911876()
    {
        $check = '<a href="https://nvd.nist.gov/vuln/detail/CVE-2019-11876" target="_blank" rel="noopener noreferrer">CVE-2019-11876</a>';
        $status = \is_dir(_PS_ROOT_DIR_ . '/install');
        $fix = $this->l('Delete folder') . ': ' . _PS_ROOT_DIR_ . \DIRECTORY_SEPARATOR . 'install';

        return [
            $check,
            $status,
            $fix,
        ];
    }

    private function checkCVE201819126()
    {
        $check = '<a href="https://nvd.nist.gov/vuln/detail/CVE-2018-19124" target="_blank" rel="noopener noreferrer">CVE-2018-19124</a>, ' .
                '<a href="https://nvd.nist.gov/vuln/detail/CVE-2018-19125" target="_blank" rel="noopener noreferrer">CVE-2018-19125</a>, ' .
                '<a href="https://nvd.nist.gov/vuln/detail/CVE-2018-19126" target="_blank" rel="noopener noreferrer">CVE-2018-19126</a>';

        $status = false;

        if ((Tools::version_compare(_PS_VERSION_, '1.6', '==') && Tools::version_compare(_PS_VERSION_, '1.6.1.23', '<')) || (Tools::version_compare(_PS_VERSION_, '1.7', '==') && Tools::version_compare(_PS_VERSION_, '1.7.4.4', '<'))) {
            if (\extension_loaded('phar') && !\ini_get('phar.readonly')) {
                $status = true;
            }
        }

        $fix = $this->l('Set') . ' "phar.readonly = Off" ' . $this->l('in your php.ini file.');

        return [
            $check,
            $status,
            $fix,
        ];
    }

    private function checkCVE201813784()
    {
        $check = '<a href="https://nvd.nist.gov/vuln/detail/CVE-2018-13784" target="_blank" rel="noopener noreferrer">CVE-2018-13784</a>';

        $status = false;

        if ((Tools::version_compare(_PS_VERSION_, '1.6', '==') && Tools::version_compare(_PS_VERSION_, '1.6.1.20', '<')) || (Tools::version_compare(_PS_VERSION_, '1.7', '==') && Tools::version_compare(_PS_VERSION_, '1.7.3.4', '<'))) {
            $status = true;
        }
        $fix = $this->l('Update PrestaShop to latest version.');

        return [
            $check,
            $status,
            $fix,
        ];
    }

    private function checkCVE20188824()
    {
        $check = '<a href="https://nvd.nist.gov/vuln/detail/CVE-2018-8823" target="_blank" rel="noopener noreferrer">CVE-2018-8823</a>, <a href="https://nvd.nist.gov/vuln/detail/CVE-2018-8824" target="_blank" rel="noopener noreferrer">CVE-2018-8824</a>';

        $status = false;

        if (\file_exists(_PS_MODULE_DIR_ . 'bamegamenu/ajax_phpcode.php')) {
            $moduleVersion = Module::getInstanceByName('bamegamenu')->version;
            if (!empty($moduleVersion)) {
                if (Tools::version_compare($moduleVersion, '1.0.32', '<=')) {
                    $status = true;
                }
            }
        }
        $fix = $this->l('Update module') . '" Responsive Mega Menu (Horizontal+Vertical+Dropdown) Pro"';

        return [
            $check,
            $status,
            $fix,
        ];
    }

    private function checkCVE20187491()
    {
        $check = '<a href="https://nvd.nist.gov/vuln/detail/CVE-2018-7491" target="_blank" rel="noopener noreferrer">CVE-2018-7491</a>';

        if (Language::countActiveLanguages() > 1) {
            $url = $this->getBaseURL() . '/' . $this->context->language->iso_code . '/';
        } else {
            $url = $this->getBaseURL();
        }

        $headers = @\get_headers($url, 1);

        $status = true;

        if ('sameorigin' === \is_array(Tools::strtolower(!empty($headers['X-Frame-Options']) ? $headers['X-Frame-Options'] : '')) ||
            'sameorigin' === Tools::strtolower(!empty($headers['X-Frame-Options']) ? $headers['X-Frame-Options'] : '') ||
            Configuration::get('LITE_CLICK_JACKING')) {
            $status = false;
        }

        $fix = $this->l('Enable') . $this->l('Click-jack protection') . ' ' . $this->l('in') . ' "' . $this->l('HTTP headers') . '" ' . $this->l('above') . '.';

        return [
            $check,
            $status,
            $fix,
        ];
    }

    private function checkCVE20151175()
    {
        $check = '<a href="https://nvd.nist.gov/vuln/detail/CVE-2018-1175" target="_blank" rel="noopener noreferrer">CVE-2015-1175</a>';

        $status = false;

        if (\file_exists(_PS_MODULE_DIR_ . 'blocklayered/blocklayered-ajax.php')) {
            $moduleVersion = Module::getInstanceByName('blocklayered')->version;
            if (!empty($moduleVersion) && Tools::version_compare($moduleVersion, '2.0.7', '<')) {
                $status = true;
            }
        }

        $fix = $this->l('Update') . ' "blocklayered" ' . $this->l('module') . '.';

        return [
            $check,
            $status,
            $fix,
        ];
    }

    private function checkCVE20179841()
    {
        $check = '<a href="https://nvd.nist.gov/vuln/detail/CVE-2017-9841" target="_blank" rel="noopener noreferrer">CVE-2017-9841</a>';

        $status = false;

        if (!empty($this->checkFilesCVE20179841())) {
            $status = true;
        }

        $fix = $this->l('Delete') . ' phpunit ' . $this->l('folders') . ':<br>' . \implode('<br>', $this->checkFilesCVE20179841());

        return [
            $check,
            $status,
            $fix,
        ];
    }

    /**
     * Check if PHP version is up to date.
     *
     * @return array
     */
    private function checkPhpVersion()
    {
        $check = $this->l('PHP version') . ' (' . Tools::checkPhpVersion() . ')';

        if (Tools::version_compare(_PS_VERSION_, '1.7.4', '<=')) {
            $status = Tools::version_compare(Tools::checkPhpVersion(), '7.1.0', '<=');
            $fix = $this->proFeature;
        } else {
            $status = Tools::version_compare(Tools::checkPhpVersion(), '7.2.0', '<=');
            $fix = $this->proFeature;
        }

        return [
            $check,
            $status,
            $fix,
        ];
    }

    /**
     * Check if PrestaShop SSL is enabled.
     *
     * @return array
     */
    private function checkSslEnabled()
    {
        $check = $this->l('SSL enabled');
        $status = false === (bool) Configuration::get('PS_SSL_ENABLED');

        $fix = $this->proFeature;

        return [
            $check,
            $status,
            $fix,
        ];
    }

    /**
     * Check if PrestaShop SSL everywhere is enabled.
     *
     * @return array
     */
    private function checkSslEnabledEverywhere()
    {
        $check = $this->l('SSL Enabled everywhere');
        $status = false === (bool) Configuration::get('PS_SSL_ENABLED_EVERYWHERE');
        $fix = $this->proFeature;

        return [
            $check,
            $status,
            $fix,
        ];
    }

    /**
     * Check if PrestaShop token is activated.
     *
     * @return array
     */
    private function checkPrestashopToken()
    {
        $check = $this->l('PrestaShop token');
        $status = false === (bool) Configuration::get('PS_TOKEN_ENABLE');
        $fix = $this->proFeature;

        return [
            $check,
            $status,
            $fix,
        ];
    }

    /**
     * Check if Mod Secure is active.
     *
     * @return array
     */
    private function checkModSecurity()
    {
        $check = 'Mod Security';
        $status = (bool) Configuration::get('PS_HTACCESS_DISABLE_MODSEC');
        $fix = $this->proFeature;

        return [
            $check,
            $status,
            $fix,
        ];
    }

    /**
     * Check if PrestaShop admin directory name is secure.
     *
     * @return array
     */
    private function checkAdminDirectoryName()
    {
        $check = $this->l('PrestaShop admin directory name');
        $status = !\preg_match('/[A-Za-z].*[0-9]|[0-9].*[A-Za-z]/', \basename(_PS_ADMIN_DIR_));
        $fix = $this->proFeature;

        return [
            $check,
            $status,
            $fix,
        ];
    }

    /**
     * Check if PrestaShop table prefix is different from default.
     *
     * @return array
     */
    private function checkPsTablePrefix()
    {
        $check = $this->l('Database table prefix');

        if (!\defined('_TB_VERSION_')) {
            $status = 'ps_' === _DB_PREFIX_;
            $fix = $this->proFeature;
        } else {
            $status = 'tb_' === _DB_PREFIX_;
            $fix = $this->proFeature;
        }

        return [
            $check,
            $status,
            $fix,
        ];
    }

    /**
     * Check if PrestaShop develop mode is active.
     *
     * @return array
     */
    private function checkPrestashopDevMode()
    {
        $check = $this->l('PrestaShop debug mode');
        $status = _PS_MODE_DEV_;
        $fix = $this->proFeature;

        return [
            $check,
            $status,
            $fix,
        ];
    }

    /**
     * Check CVE-2020-5250.
     *
     * @return array
     */
    private function checkCVE20205250()
    {
        $check = '<a href="https://nvd.nist.gov/vuln/detail/CVE-2020-5250" target="_blank" rel="noopener noreferrer">CVE-2020-5250</a>';

        $status = false;
        if (Tools::version_compare(_PS_VERSION_, '1.7.0.0', '>=') && Tools::version_compare(_PS_VERSION_, '1.7.6.4', '<')) {
            $status = true;
        }

        $fix = $this->l('Update PrestaShop to latest version.');

        return [
            $check,
            $status,
            $fix,
        ];
    }

    /**
     * Check php.ini conf: session.use_cookies.
     *
     * @return array
     */
    private function checkSessionUseCookies()
    {
        $key = 'session.use_cookies';
        if (false !== $this->isOn(\ini_get($key))) {
            $current = $this->isOn(\ini_get($key));
        } else {
            $current = '1';
        }

        return [
            $key,
            $current,
        ];
    }

    /**
     * Check php.ini conf: session.use_only_cookies.
     *
     * @return array
     */
    private function checkSessionUseOnlyCookies()
    {
        $key = 'session.use_only_cookies';
        if (false !== $this->isOn(\ini_get($key))) {
            $current = $this->isOn(\ini_get($key));
        } else {
            $current = '1';
        }

        return [
            $key,
            $current,
        ];
    }

    /**
     * Check php.ini conf: session.cookie_httponly.
     *
     * @return array
     */
    private function checkSessionCookieHttponly()
    {
        $key = 'session.cookie_httponly';
        if (false !== $this->isOn(\ini_get($key))) {
            $current = $this->isOn(\ini_get($key));
        } else {
            $current = '';
        }

        return [
            $key,
            $current,
        ];
    }

    /**
     * Check php.ini conf: session.hash_function.
     *
     * @return array
     */
    private function checkAessionHashFunction()
    {
        $key = 'session.hash_function';

        if (false !== $this->isOn(\ini_get($key))) {
            $current = $this->isOn(\ini_get($key));
        } else {
            $current = '0';
        }

        return [
            $key,
            $current,
        ];
    }

    /**
     * Check php.ini conf: session.use_trans_sid.
     *
     * @return array
     */
    private function checkPhpUseTransSid()
    {
        $key = 'session.use_trans_sid';
        if (false !== $this->isOn(\ini_get($key))) {
            $current = $this->isOn(\ini_get($key));
        } else {
            $current = '0';
        }

        return [
            $key,
            $current,
        ];
    }

    /**
     * Check php.ini conf: session.cookie_secure.
     *
     * @return array
     */
    private function checkCookieSecure()
    {
        $key = 'session.cookie_secure';
        if (false !== $this->isOn(\ini_get($key))) {
            $current = $this->isOn(\ini_get($key));
        } else {
            $current = '';
        }

        return [
            $key,
            $current,
        ];
    }

    /**
     * Check php.ini conf: session.cookie_lifetime.
     *
     * @return array
     */
    private function checkCookieLifetime()
    {
        $key = 'session.cookie_lifetime';
        if (false !== $this->isOn(\ini_get($key))) {
            $current = $this->isOn(\ini_get($key));
        } else {
            $current = '0';
        }

        return [
            $key,
            $current,
        ];
    }

    /**
     * Check php.ini conf: session.use_strict_mode.
     *
     * @return array
     */
    private function checkUseScrickMode()
    {
        $key = 'session.use_strict_mode';
        if (false !== $this->isOn(\ini_get($key))) {
            $current = $this->isOn(\ini_get($key));
        } else {
            $current = '0';
        }

        return [
            $key,
            $current,
        ];
    }

    /**
     * Check php.ini conf: session.lazy_write.
     *
     * @return array
     */
    private function checkLazyWrite()
    {
        $key = 'session.lazy_write';

        if (false !== $this->isOn(\ini_get($key))) {
            $current = $this->isOn(\ini_get($key));
        } else {
            $current = '0';
        }

        return [
            $key,
            $current,
        ];
    }

    /**
     * Check php.ini conf: session.sid_length.
     *
     * @return array
     */
    private function checkSidLength()
    {
        $key = 'session.sid_length';

        if (false !== \ini_get($key)) {
            $current = \ini_get($key);
        } else {
            $current = '32';
        }

        return [
            $key,
            $current,
        ];
    }

    private function checkSessionGcDivisor()
    {
        $key = 'session.gc_divisor';
        if (false !== $this->isOn(\ini_get($key))) {
            $current = $this->isOn(\ini_get($key));
        } else {
            $current = '1';
        }

        return [
            $key,
            $current,
        ];
    }

    /**
     * Check php.ini conf: session.sid_bits_per_character.
     *
     * @return array
     */
    private function checkSidBitsPerCharacter()
    {
        $key = 'session.sid_bits_per_character';

        if (false !== \ini_get($key)) {
            $current = \ini_get($key);
        } else {
            $current = '4';
        }

        return [
            $key,
            $current,
        ];
    }

    /**
     * Check php.ini conf: allow_url_fopen.
     *
     * @return array
     */
    private function checkUrlFopen()
    {
        $key = 'allow_url_fopen';
        if (false !== $this->isOn(\ini_get($key))) {
            $current = $this->isOn(\ini_get($key));
        } else {
            $current = '1';
        }

        return [
            $key,
            $current,
        ];
    }

    /**
     * Check php.ini conf: allow_url_include.
     *
     * @return array
     */
    private function checkUrlInclude()
    {
        $key = 'allow_url_include';
        if (false !== $this->isOn(\ini_get($key))) {
            $current = $this->isOn(\ini_get($key));
        } else {
            $current = '1';
        }

        return [
            $key,
            $current,
        ];
    }

    /**
     * Check php.ini conf: display_errors.
     *
     * @return array
     */
    private function checkDisplayErrors()
    {
        $key = 'display_errors';
        if (false !== $this->isOn(\ini_get($key))) {
            $current = $this->isOn(\ini_get($key));
        } else {
            $current = '1';
        }

        return [
            $key,
            $current,
        ];
    }

    /**
     * Check php.ini conf: log_errors.
     *
     * @return array
     */
    private function checkLogErrors()
    {
        $key = 'log_errors';
        if (false !== $this->isOn(\ini_get($key))) {
            $current = $this->isOn(\ini_get($key));
        } else {
            $current = '0';
        }

        return [
            $key,
            $current,
        ];
    }

    /**
     * Check php.ini conf: expose_php.
     *
     * @return array
     */
    private function checkExposePhp()
    {
        $key = 'expose_php';
        if (false !== $this->isOn(\ini_get($key))) {
            $current = $this->isOn(\ini_get($key));
        } else {
            $current = '1';
        }

        return [
            $key,
            $current,
        ];
    }

    /**
     * Check php.ini conf: register_globals.
     *
     * @return array
     */
    private function checkRegisterGlobals()
    {
        $key = 'register_globals';
        if (false !== $this->isOn(\ini_get($key))) {
            $current = $this->isOn(\ini_get($key));
        } else {
            $current = '0';
        }

        return [
            $key,
            $current,
        ];
    }

    /**
     * Check php.ini conf: register_argc_argv.
     *
     * @return array
     */
    private function checkRegisterArgcArgv()
    {
        $key = 'register_argc_argv';
        if (false !== $this->isOn(\ini_get($key))) {
            $current = $this->isOn(\ini_get($key));
        } else {
            $current = '0';
        }

        return [
            $key,
            $current,
        ];
    }

    /**
     * Check php.ini conf: short_open_tag.
     *
     * @return array
     */
    private function checkShortOpenTag()
    {
        $key = 'short_open_tag';
        if (false !== $this->isOn(\ini_get($key))) {
            $current = $this->isOn(\ini_get($key));
        } else {
            $current = '1';
        }

        return [
            $key,
            $current,
        ];
    }

    /**
     * Check php.ini conf: post_max_size.
     *
     * @return array
     */
    private function checkPostMaxSize()
    {
        $key = 'post_max_size';
        if (false !== \ini_get($key)) {
            $current = \ini_get($key);
        } else {
            $current = '8M';
        }

        return [
            $key,
            $current,
        ];
    }

    /**
     * Check php.ini conf: max_input_vars.
     *
     * @return array
     */
    private function checkMaxInputVars()
    {
        $key = 'max_input_vars';
        if (false !== \ini_get($key)) {
            $current = \ini_get($key);
        } else {
            $current = '1000';
        }

        return [
            $key,
            $current,
        ];
    }

    /**
     * Check php.ini conf: max_input_vars.
     *
     * @return array
     */
    private function checkMaxInputTime()
    {
        $key = 'max_input_time';
        if (false !== \ini_get($key)) {
            $current = \ini_get($key);
        } else {
            $current = '-1';
        }

        return [
            $key,
            $current,
        ];
    }

    /**
     * Check php.ini conf: display_startup_errors.
     *
     * @return array
     */
    private function checkDisplayStartupErrors()
    {
        $key = 'display_startup_errors';
        if (false !== $this->isOn(\ini_get($key))) {
            $current = $this->isOn(\ini_get($key));
        } else {
            $current = '0';
        }

        return [
            $key,
            $current,
        ];
    }

    /**
     * Check php.ini conf: error_reporting.
     *
     * @return array
     */
    private function checkErrorReporting()
    {
        $key = 'error_reporting';
        if (false !== $this->isOn(\ini_get($key))) {
            $current = $this->isOn(\ini_get($key));
        } else {
            $current = '0';
        }

        return [
            $key,
            $current,
        ];
    }

    /**
     * Check php.ini conf: upload_max_filesize.
     *
     * @return array
     */
    private function checkUploadMaxFileSize()
    {
        $key = 'upload_max_filesize';
        if (false !== \ini_get($key)) {
            $current = \ini_get($key);
        } else {
            $current = '2M';
        }

        return [
            $key,
            $current,
        ];
    }

    /**
     * Check php.ini conf: memory_limit.
     *
     * @return array
     */
    private function checkMemoryLimit()
    {
        $key = 'memory_limit';
        if (false !== \ini_get($key)) {
            $current = \ini_get($key);
        } else {
            $current = '128M';
        }

        return [
            $key,
            $current,
        ];
    }

    /**
     * Check php.ini conf: default_charset.
     *
     * @return array
     */
    private function checkDefaultCharset()
    {
        $key = 'default_charset';
        if (false !== \ini_get($key)) {
            $current = \ini_get($key);
        } else {
            $current = 'utf-8';
        }

        return [
            $key,
            $current,
        ];
    }

    /**
     * Check php.ini conf: xdebug.default_enable.
     *
     * @return array
     */
    private function checkXdebugDefaultEnable()
    {
        $key = 'xdebug.default_enable';
        if (false !== $this->isOn(\ini_get($key))) {
            $current = $this->isOn(\ini_get($key));
        } else {
            $current = '0';
        }

        return [
            $key,
            $current,
        ];
    }

    /**
     * Check php.ini conf: xdebug.remote_enable.
     *
     * @return array
     */
    private function checkXdebugRemoteEnable()
    {
        $key = 'xdebug.remote_enable';
        if (false !== $this->isOn(\ini_get($key))) {
            $current = $this->isOn(\ini_get($key));
        } else {
            $current = '0';
        }

        return [
            $key,
            $current,
        ];
    }

    /**
     * Check php.ini conf: max_execution_time.
     *
     * @return array
     */
    private function checkMaxExecutionTime()
    {
        $key = 'max_execution_time';
        if (false !== \ini_get($key)) {
            $current = \ini_get($key);
        } else {
            $current = '30';
        }

        return [
            $key,
            $current,
        ];
    }

    /**
     * Check php.ini conf: file_uploads.
     *
     * @return array
     */
    private function checkFileUploads()
    {
        $key = 'file_uploads';
        if (false !== $this->isOn(\ini_get($key))) {
            $current = $this->isOn(\ini_get($key));
        } else {
            $current = '1';
        }

        return [
            $key,
            $current,
        ];
    }

    /**
     * Get URL of shop.
     *
     * @return string
     */
    private function getShopUrl()
    {
        if (Language::countActiveLanguages() > 1) {
            return $this->getBaseURL() . $this->context->language->iso_code . '/';
        }

        return $this->getBaseURL();
    }

    /**
     * Add missing index.php files.
     *
     * @param string $path
     */
    private function addIndexRecursively($path)
    {
        if (0 === \mb_strpos(\basename($path), '.')) {
            return;
        }

        $indexFilePath = $path . \DIRECTORY_SEPARATOR . 'index.php';

        if (false === \file_exists($indexFilePath)) {
            \file_put_contents($path . \DIRECTORY_SEPARATOR . 'index.php', Tools::getDefaultIndexContent());
        }

        $dirs = \glob($path . \DIRECTORY_SEPARATOR . '*', \GLOB_ONLYDIR);

        if (false === $dirs) {
            return;
        }

        foreach ($dirs as $dir) {
            $this->addIndexRecursively($dir);
        }
    }

    /**
     * change file- and directory permissions.
     *
     * @param string $dir
     */
    private function chmodFileDirectory($dir)
    {
        $perms = [];
        $perms['file'] = 0644;
        $perms['directory'] = 0755;
        $errorDir = null;
        $errorFile = null;
        $dh = @\opendir($dir);

        if ($dh) {
            while (false !== ($file = \readdir($dh))) {
                if ('.' !== $file && '..' !== $file) {
                    $fullPath = $dir . \DIRECTORY_SEPARATOR . $file;

                    if (!\is_dir($fullPath)) {
                        if (!\chmod($fullPath, $perms['file'])) {
                            $errorFile .= '<strong>' . $this->l('Failed') . '</strong> ' . $this->l('to set file permissions on') . ' ' . $fullPath . \PHP_EOL;
                        }
                    } else {
                        if (\chmod($fullPath, $perms['directory'])) {
                            $this->chmodFileDirectory($fullPath);
                        } else {
                            $errorDir .= '<strong>' . $this->l('Failed') . '</strong> ' . $this->l('to set directory permissions on') . ' ' . $fullPath . \PHP_EOL;
                        }
                    }
                }
            }
            \closedir($dh);
        }
    }

    /**
     * Block custom list of IP addresses.
     */
    private function blockIp()
    {
        if (Tools::isEmpty(Configuration::get('LITE_BAN_IP')) && false === Configuration::get('LITE_BAN_IP')) {
            return false;
        }

        $blacklist = \explode(',', Configuration::get('LITE_BAN_IP'));
        foreach ($blacklist as &$list) {
            $range = \IPLib\Factory::rangeFromString($list);
            if ($range->contains(\IPLib\Factory::addressFromString(\Tools::getRemoteAddr()))) {
                return true;
            }
        }

        return false;
    }

    /**
     * Block custom list of User agents.
     */
    private function blockUserAgent()
    {
        if (!empty($_SERVER['HTTP_USER_AGENT'])) {
            $userAgent = $_SERVER['HTTP_USER_AGENT'];
            $blacklist = \explode(',', Configuration::get('LITE_BLOCK_USER_AGENT'));
            foreach ($blacklist as &$list) {
                if (false !== \mb_strpos($userAgent, $list)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Lookup eldest access try by specific e-mail in database.
     *
     * @param string $email
     *
     * @return int
     */
    private function getEldestAccessTry($email)
    {
        $maxRetry = (int) Configuration::get('LITE_MAX_RETRY');
        $email = pSQL($email);
        $query = 'SELECT IF(COUNT(*) = ' . $maxRetry . ', MIN(access_time), \'0000-00-00 00:00:00\') AS access_time FROM (SELECT access_time FROM ' . _DB_PREFIX_ . 'securitylite WHERE banned = 0 AND email = "' . $email . '" ORDER BY access_time DESC LIMIT ' . $maxRetry . ') tmp';
        $accessStats = Db::getInstance()->getRow($query);

        return $accessStats ? \strtotime($accessStats['access_time']) : 0;
    }

    /**
     * Check CVE-2017-9841.
     *
     * @return array
     */
    private function checkFilesCVE20179841()
    {
        $result = [];

        $rootPath = _PS_CORE_DIR_ . \DIRECTORY_SEPARATOR . 'vendor' . \DIRECTORY_SEPARATOR . 'phpunit';
        if (\is_dir($rootPath)) {
            $result[] .= $rootPath;
        }

        $modulePath = _PS_MODULE_DIR_;

        $iter = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($modulePath, RecursiveDirectoryIterator::SKIP_DOTS),
            RecursiveIteratorIterator::SELF_FIRST,
            RecursiveIteratorIterator::CATCH_GET_CHILD // Ignore "Permission denied"
        );

        $paths = [$modulePath];
        foreach ($iter as $path => $dir) {
            if ($dir->isDir()) {
                $paths[] = $path;
                if ('phpunit' === $dir->getFilename()) {
                    $result[] .= $dir->getRealpath();
                }
            }
        }

        return $result;
    }

    /**
     * Response HTTP header 403 and block the request.
     */
    private function blockRequest()
    {
        \http_response_code(403);
        \header('Connection: Close');
        \header('Cache-Control: max-age=0, private, no-store, no-cache, must-revalidate');
        exit;
    }

    /**
     * Normalize php ini value.
     *
     * @param $v string
     *
     * @return bool
     */
    private function isOn($v)
    {
        if ('0' === $v || false === $v || 'off' === Tools::strtolower($v)) {
            return '0';
        }

        return '1';
    }

    /**
     * Download a compressed zip file with all translations.
     */
    private function exportTranslation()
    {
        $date = \time();
        $backupFile = 'securitylite-trans-' . $date . '.zip';
        $ignoreFiles = [
            'index.php',
        ];
        $dir = _PS_MODULE_DIR_ . 'securitylite/translations';

        $directoryIterator = new RecursiveDirectoryIterator($dir);

        $ignoreIterator = new \PhpZip\Util\Iterator\IgnoreFilesRecursiveFilterIterator(
            $directoryIterator,
            $ignoreFiles
        );

        $zipFile = new \PhpZip\ZipFile();
        $zipFile->setCompressionLevel(\PhpZip\Constants\ZipCompressionLevel::SUPER_FAST);
        $zipFile->addFilesFromIterator($ignoreIterator, \PhpZip\Constants\ZipCompressionMethod::STORED);
        $zipFile->outputAsAttachment($backupFile);
        exit;
    }
}
