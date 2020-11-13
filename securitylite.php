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

$autoloadPath = _PS_MODULE_DIR_ . 'securitylite/vendor/autoload.php';
if (\file_exists($autoloadPath)) {
    require_once $autoloadPath;
}

class SecurityLite extends Module
{
    const LOG_BRUTE_FORCE = 'sl_bruteforce.log';
    const LOG_PAGE_NOT_FOUND = 'sl_pagenotfound.log';
    const LOG_FIREWALL = 'sl_firewall.log';
    const LOG_MALWARE_SCAN = 'sl_malwarescan.log';
    const LOG_FILE_CHANGES = 'sl_file_changes.log';
    const LOG_CRONJOB = 'sl_cron.log';
    const DIR_BACKUP_DATABASE = '/backup/database/';
    const REPORT_PORT_SCANNER = 'sl_report_port_scanner.txt';
    const REPORT_RBL_CHECKER = 'sl_report_rbl_checker.txt';
    const REPORT_CREATE_INDEX = 'sl_report_create_index.txt';
    const REPORT_PERMISSIONS = 'sl_report_permissions.txt';
    const REPORT_REMOVE_FILES = 'sl_report_remove_files.txt';
    const COLOR_GREEN = '#78d07d';
    const COLOR_RED = '#e08f95';
    const COLOR_BLUE = '#4ac7e0';

    /** @var int */
    public $cron = 0;

    /**
     * Construct module.
     */
    public function __construct()
    {
        $this->name = 'securitylite';
        $this->tab = 'administration';
        $this->version = '5.0.0';
        $this->author = 'Mathias Reker';
        $this->module_key = '';
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
        $this->proFeature = '<span style="color:#e50b70; font-weight:bold;">' . $this->l('PRO FEATURE') . '</span> ';
    }

    /**
     * Install module, database table and set default values.
     *
     * @return bool
     */
    public function install()
    {
        if (Shop::isFeatureActive()) {
            Shop::setContext(Shop::CONTEXT_ALL);
        }

        $sql = [];

        $sql[] = 'CREATE TABLE IF NOT EXISTS `' . _DB_PREFIX_ . 'securitylite` (
            `id_securitylite` int(11) NOT NULL,
            `email` varchar(64) NOT NULL,
            `access_time` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
            `ip` varchar(64) NOT NULL,
            `banned` int(1) NOT NULL
            ) ENGINE=' . _MYSQL_ENGINE_ . ' DEFAULT CHARSET=UTF8;
            ALTER TABLE `' . _DB_PREFIX_ . 'securitylite`
              ADD PRIMARY KEY (`id_securitylite`);
            ALTER TABLE `' . _DB_PREFIX_ . 'securitylite`
              MODIFY `id_securitylite` int(11) NOT NULL AUTO_INCREMENT;';

        $sql[] = 'CREATE TABLE IF NOT EXISTS `' . _DB_PREFIX_ . 'securitylite_tfa` (
            `enabled` int(1) NOT NULL,
            `secret` varchar(32) NOT NULL
            ) ENGINE=' . _MYSQL_ENGINE_ . ' DEFAULT CHARSET=UTF8;
            ';

        foreach ($sql as $query) {
            if (false === Db::getInstance()->execute($query)) {
                return false;
            }
        }

        $this->installTab();

        Configuration::updateValue('LITE_BAN_TIME', 30);
        Configuration::updateValue('LITE_MAX_RETRY', 5);
        Configuration::updateValue('LITE_FIND_TIME', 10);
        Configuration::updateValue('LITE_ADMIN_DIRECTORY_NAME', \basename(_PS_ADMIN_DIR_));
        Configuration::updateValue('LITE_DELETE_OLD_CARTS_DAYS', 14);
        Configuration::updateValue('LITE_BACKUP_DB_SAVED', 7);
        Configuration::updateValue('LITE_ADVANCED_MAINTENANCE_MODE_COMPANY', Configuration::get('PS_SHOP_NAME'));

        $address = [];
        if (true === (bool) Configuration::get('PS_SHOP_ADDR1')) {
            $address[] = Configuration::get('PS_SHOP_ADDR1');
        }
        if (true === (bool) Configuration::get('PS_SHOP_ADDR2')) {
            $address[] = Configuration::get('PS_SHOP_ADDR2');
        }
        if (true === (bool) Configuration::get('PS_SHOP_CODE')) {
            $address[] = Configuration::get('PS_SHOP_CODE');
        }
        if (true === (bool) Configuration::get('PS_SHOP_CITY')) {
            $address[] = Configuration::get('PS_SHOP_CITY');
        }

        if (!empty($address)) {
            Configuration::updateValue('LITE_ADVANCED_MAINTENANCE_MODE_ADDRESS', \implode(', ', $address));
        }

        if (true === (bool) Configuration::get('PS_SHOP_PHONE')) {
            Configuration::updateValue('LITE_ADVANCED_MAINTENANCE_MODE_PHONE', Configuration::get('PS_SHOP_PHONE'));
        }

        Configuration::updateValue('LITE_ADVANCED_MAINTENANCE_MODE_EMAIL', Configuration::get('PS_SHOP_EMAIL'));
        Configuration::updateValue('LITE_ADVANCED_MAINTENANCE_MODE_FACEBOOK', '#');
        Configuration::updateValue('LITE_ADVANCED_MAINTENANCE_MODE_TWITTER', '#');
        Configuration::updateValue('LITE_ADVANCED_MAINTENANCE_MODE_INSTAGRAM', '#');
        Configuration::updateValue('LITE_ADVANCED_MAINTENANCE_MODE_PINTEREST', '#');
        Configuration::updateValue('LITE_ADVANCED_MAINTENANCE_MODE_YOUTUBE', '#');
        Configuration::updateValue('LITE_ADVANCED_MAINTENANCE_MODE_COPYRIGHT', true);
        Configuration::updateValue('LITE_ADVANCED_MAINTENANCE_MODE_LOGO_PATH', _PS_IMG_ . Configuration::get('PS_LOGO'));
        Configuration::updateValue('LITE_ADVANCED_MAINTENANCE_MODE_LOGO', true);
        Configuration::updateValue('LITE_ANTI_FRAUD_UNIT', 'km');
        Configuration::updateValue('LITE_ANTI_FRAUD_HOOK', 'left');

        $hooks = [
            'displayBackOfficeTop',
            'displayHeader',
            'displayMaintenance',
        ];

        if (false === parent::install() || false === $this->registerHook($hooks)) {
            return false;
        }

        return true;
    }

    /**
     * Uninstall the module, reverse any changes and delete database table.
     *
     * @return bool
     */
    public function uninstall()
    {
        // Force default group
        if (Shop::isFeatureActive()) {
            Shop::setContext(Shop::CONTEXT_ALL);
        }

        $this->uninstallTab();

        $sql = [];

        $sql[] = 'DROP TABLE IF EXISTS `' . _DB_PREFIX_ . 'securitylite`';
        $sql[] = 'DROP TABLE IF EXISTS `' . _DB_PREFIX_ . 'securitylite_tfa`';

        foreach ($sql as $query) {
            if (false === Db::getInstance()->execute($query)) {
                return false;
            }
        }

        $this->removeHtaccessContent();

        $logs = [
            self::LOG_PAGE_NOT_FOUND,
            self::LOG_FIREWALL,
            self::LOG_BRUTE_FORCE,
            self::LOG_MALWARE_SCAN,
            self::LOG_FILE_CHANGES,
            self::LOG_CRONJOB,
        ];

        foreach ($logs as $log) {
            Tools::deleteFile($this->getLogFile($log));
        }

        foreach (\array_keys($this->getConfigFormValues()) as $key) {
            Configuration::deleteByName($key);
        }

        $this->clearCacheSecuritylite(false);

        return parent::uninstall();
    }

    /**
     * Display advanced maintenance.
     *
     * @param array $params
     */
    public function hookDisplayMaintenance($params)
    {
        if (false === (bool) Configuration::get('LITE_ADVANCED_MAINTENANCE_MODE')) {
            return;
        }

        \http_response_code(503);

        $lang = $this->context->language->iso_code;
        $company = Configuration::get('LITE_ADVANCED_MAINTENANCE_MODE_COMPANY');
        $address = Configuration::get('LITE_ADVANCED_MAINTENANCE_MODE_ADDRESS');
        $phone = Configuration::get('LITE_ADVANCED_MAINTENANCE_MODE_PHONE');
        $email = Configuration::get('LITE_ADVANCED_MAINTENANCE_MODE_EMAIL');
        $facebook = Configuration::get('LITE_ADVANCED_MAINTENANCE_MODE_FACEBOOK');
        $twitter = Configuration::get('LITE_ADVANCED_MAINTENANCE_MODE_TWITTER');
        $instagram = Configuration::get('LITE_ADVANCED_MAINTENANCE_MODE_INSTAGRAM');
        $pinterest = Configuration::get('LITE_ADVANCED_MAINTENANCE_MODE_PINTEREST');
        $youtube = Configuration::get('LITE_ADVANCED_MAINTENANCE_MODE_YOUTUBE');
        $shopName = Configuration::get('PS_SHOP_NAME');
        $logoPath = Configuration::get('LITE_ADVANCED_MAINTENANCE_MODE_LOGO_PATH');
        $copyright = Configuration::get('LITE_ADVANCED_MAINTENANCE_MODE_COPYRIGHT');
        $showLogo = Configuration::get('LITE_ADVANCED_MAINTENANCE_MODE_LOGO');
        $message = $this->l('Our webserver is currently down for scheduled maintenance. We expect to be back very soon. Apologies for the inconvenience!');
        $title = $this->l('Coming soon');

        $logoOutput = null;
        if (true === (bool) $showLogo) {
            if (false === (bool) $logoPath) {
                $logoPath = _PS_IMG_ . Configuration::get('PS_LOGO');
            }
            $logoOutput = '<img class="masthead-brand" src="' . $logoPath . '" alt="">';
        }
        $imgCover = $this->_path . 'views/img/cover.jpg';

        $copyrightOutput = null;
        if (true === (bool) $copyright) {
            if (true === (bool) $company) {
                $copyrightOutput = '<p>&copy; ' . \date('Y') . ' ' . $company . '</p>';
            }
        }
        $addressArray = \array_filter([
            $company,
            $address,
            $phone,
            $email,
        ]);

        if (!empty($addressArray)) {
            $addressOutput = '<p>' . \implode(' | ', $addressArray) . '</p>';
        } else {
            $addressOutput = null;
        }

        if (false !== (bool) $facebook) {
            $facebookLink = '<a class="nav-link nav-social" href="' . $facebook . '"><i class="fab fa-facebook" aria-hidden="true"></i></a>';
        } else {
            $facebookLink = null;
        }

        if (false !== (bool) $twitter) {
            $twitterLink = '<a class="nav-link nav-social" href="' . $twitter . '"><i class="fab fa-twitter" aria-hidden="true"></i></a>';
        } else {
            $twitterLink = null;
        }

        if (false !== (bool) $instagram) {
            $instagramLink = '<a class="nav-link nav-social" href="' . $instagram . '"><i class="fab fa-instagram" aria-hidden="true"></i></a>';
        } else {
            $instagramLink = null;
        }

        if (false !== (bool) $pinterest) {
            $pinterestLink = '<a class="nav-link nav-social" href="' . $pinterest . '"><i class="fab fa-pinterest" aria-hidden="true"></i></a>';
        } else {
            $pinterestLink = null;
        }

        if (false !== (bool) $youtube) {
            $youtubeLink = '<a class="nav-link nav-social" href="' . $youtube . '"><i class="fab fa-youtube" aria-hidden="true"></i></a>';
        } else {
            $youtubeLink = null;
        }

        $socialMediaArray = \array_filter([
            $facebookLink,
            $twitterLink,
            $instagramLink,
            $pinterestLink,
            $youtubeLink,
        ]);

        $socialMediaOutput = \implode('', $socialMediaArray);

        $bootstrap = '<link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" integrity="sha384-JcKb8q3iqJ61gNV9KGb8thSsNjpSL0n8PARn9HuZOnIxN0hoP+VmmDGMN5t9UJ0Z" crossorigin="anonymous">';

        $fontAwesome = '<link rel="stylesheet" href="https://use.fontawesome.com/releases/v5.15.0/css/all.css" crossorigin="anonymous">';

        $style = '<style>a,a:focus,a:hover{color: #fff;}html,body{height: 100%;}body{background: url(' . $imgCover . ') no-repeat center center fixed; background-size: cover; color: #fff; text-align: center; font-family: "Roboto", Helvetica, Arial, sans-serif;}.site-wrapper{display: table; width: 100%; height: 100%; min-height: 100%; background: rgba(48, 53, 70, 0.5); box-shadow: inset 0 0 100px rgba(0, 0, 0, 0.5);}.site-wrapper-inner{display: table-cell; vertical-align: top;}.cover-container{margin-right: auto; margin-left: auto;}.inner{padding: 30px;}.masthead-brand{margin-top: 10px; margin-bottom: 10px;}.nav-masthead{text-align: center; display: block;}.nav-masthead .nav-link{display: inline-block;}@media (min-width: 768px){.masthead-brand{float: left;}.nav-masthead{float: right;}}.cover{padding: 0 20px;}.cover-heading{font-weight: 500; text-transform: uppercase; letter-spacing: 10px; font-size: 2rem; margin-bottom: 5rem;}@media (min-width: 768px){.cover-heading{font-size: 3.4rem; letter-spacing: 15px;}}.cover-copy{max-width: 500px; margin: 0 auto 3rem;}.mastfoot{color: #999; color: rgba(255, 255, 255, 0.5);}@media (min-width: 768px){.masthead{position: fixed; top: 0;}.mastfoot{position: fixed; bottom: 0;}.site-wrapper-inner{vertical-align: middle;}.masthead, .mastfoot, .cover-container{width: 100%;}}@media (min-width: 992px){.masthead, .mastfoot, .cover-container{width: 1060px;}}</style>';

        echo '<!DOCTYPE html><html lang="' . $lang . '"> <head> <meta charset="utf-8"> <meta http-equiv="X-UA-Compatible" content="IE=edge"> <meta name="viewport" content="width=device-width, initial-scale=1"> ' . $fontAwesome . $bootstrap . $this->getFavicon() . ' <title>' . $shopName . ' ' . $this->l('is in maintenance mode') . '</title> <meta name="description" content="' . $message . '">' . $style . ' </head> <body id="top"> <div class="site-wrapper"> <div class="site-wrapper-inner"> <div class="cover-container"> <div class="masthead clearfix"> <div class="inner"> ' . $logoOutput . ' <nav class="nav nav-masthead">' . $socialMediaOutput . '</nav> </div></div><br><div class="inner cover"> <h1 class="cover-heading">' . $title . '</h1> <p class="lead cover-copy">' . $message . '</p></div><div class="mastfoot"> <div class="inner"> ' . $addressOutput . $copyrightOutput . ' </div></div></div></div></div></body></html>';
        exit;
    }

    /**
     * Run scripts depending on configuration. Display warnings and confirmations.
     *
     * @return array
     */
    public function getContent()
    {
        if (Shop::isFeatureActive()) {
            Shop::setContext(Shop::CONTEXT_ALL);
        }

        $clientIp = \Tools::getRemoteAddr();

        $out = [];

        $out[] = '<style>#overlay{background:#fff;color:#666;position:fixed;height:100%;width:100%;z-index:5000;top:0;left:0;float:left;text-align:center;padding-top:20%}.textarea-autosize{min-height:80px}.btn,.list-group-item,a,button:focus,input[type=checkbox]:focus{outline:0!important}.securitylite-divider{width:10px;height:auto;display:inline-block}</style>';

        $out[] = '<script>window.addEventListener("load",function(){$("#overlay").fadeOut()});</script>';

        if (true === (bool) $this->context->language->is_rtl) {
            $out[] = '<style>.securitylite-position{float:left;white-space:nowrap;}</style>'; // RTL
        } else {
            $out[] = '<style>.securitylite-position{float:right;white-space:nowrap;}</style>'; // LTR
        }

        // Hide confirmation message after 10 sec.
        $out[] = '<script>$(document).ready(function(){setTimeout(function(){$(".module_confirmation").fadeOut("slow")},10e3)});</script>';

        $out[] = '<script>$(document).ready(function() {
    document.getElementById("LITE_MESSAGE_CHECKER_CUSTOM_LIST").disabled = !0,
    document.getElementById("LITE_EMAIL_CHECKER_CUSTOM_LIST").disabled = !0,
    document.getElementById("LITE_EMAIL_CHECKER_CUSTOM_LIST_REGISTRATION").disabled = !0,
    document.getElementById("LITE_WHITELIST_MALWARE").disabled = !0,
    document.getElementById("LITE_FILE_CHANGES_WHITELIST").disabled = !0,
    document.getElementById("LITE_HSTS_SETTINGS_0").disabled = !0,
    document.getElementById("LITE_HSTS_SETTINGS_1").disabled = !0
});</script>';

        $out[] = '<div id="overlay"> <img style="width: 60px; padding-bottom: 10px" src="' . $this->_path . 'logo.png" alt="" loading="eager"><p><strong>' . $this->l('Security Lite') . '</strong></p></div>';

        $out[] = "<script>
    function addField1() {
        $(function() {
            var pass = secureRandomPassword.randomString({
                length: 24
            });
            var text = $('#LITE_PASSWORD_GENERATOR');
            text.val(pass);
        });
    }
    function addMyIp(id) {
        if ($(id).val() !== '') {
            var comma = ',';
        } else {
            var comma = '';
        }
        $(function() {
            var pass = '" . $clientIp . "';
            var text = $(id);
            text.val(text.val() + comma + pass);
        });
    }
    function copyToClipboard(text) {
        var dummy = document.createElement('textarea');
        document.body.appendChild(dummy);
        dummy.value = text;
        dummy.select();
        document.execCommand('copy');
        document.body.removeChild(dummy);
    }
</script>"; // todo

        // Add Version tab
        if (\defined('_TB_VERSION_')) {
            $cmsName = 'Thirty bees';
            $cmsVersion = _TB_VERSION_;
        } else {
            $cmsName = 'PrestaShop';
            $cmsVersion = _PS_VERSION_;
        }

        if (true === (bool) Configuration::get('PS_DISABLE_NON_NATIVE_MODULE')) {
            $out[] = $this->displayError($this->l('You must enable non PrestaShop modules at') . ' ' . $this->generateLink($this->getAdminLink('AdminPerformance', true), $this->l('\'Advanced Parameters\' > \'Performance\'')) . '.');
        }

        $moduleVersion = Module::getInstanceByName('securitylite')->version;

        if (true === (bool) Tools::isSubmit('tab_reset')) {
            $out[] = '<script>localStorage.setItem(\'lastTab\',\'fieldset_0_securitylite\');</script>';
        }

        $out[] = '<script>$(document).ready(function() {$("#module-tabs").after("<div id=\'module-tabs\' class=\'list-group\'><a class=\'list-group-item\' style=\'text-align: center;\'><i class=\'icon-info\'></i> ' . $this->l('Version') . ' ' . $moduleVersion . ' | <i class=\'icon-info\'></i> ' . $cmsName . ' ' . $cmsVersion . '</a></div>");});</script>';

        $localBackups = [
            [
                'BackupDatabaseDownload',
                self::DIR_BACKUP_DATABASE,
            ],
        ];

        foreach ($localBackups as $localBackup) {
            if (true === (bool) Tools::isSubmit($localBackup[0])) {
                $dir = _PS_MODULE_DIR_ . $this->name . $localBackup[1];
                $file = Tools::getValue('file');

                $this->downloadFile($dir . $file);
            }
        }

        $deleteFile = false;

        $deleteLocalBackups = [
            [
                'BackupDatabaseDelete',
                self::DIR_BACKUP_DATABASE,
            ],
        ];

        foreach ($deleteLocalBackups as $deleteLocalBackup) {
            if (true === (bool) Tools::isSubmit($deleteLocalBackup[0])) {
                $dir = _PS_MODULE_DIR_ . $this->name . $deleteLocalBackup[1];
                $file = Tools::getValue('file');
                Tools::deleteFile($dir . $file);
                $deleteFile = true;
            }
        }

        if (true === $deleteFile) {
            if (\file_exists($file)) {
                $out[] = $this->displayConfirmation($this->l('File') . ' <strong>' . $dir . $file . '</strong> ' . $this->l('has been deleted.'));
            }
        }

        // Clear cache
        if (true === (bool) Tools::isSubmit('clear_cache')) {
            $this->clearCacheSecuritylite(true);

            $out[] = $this->displayConfirmation($this->l('All caches cleared successfully.'));
        }

        // Logs
        if (true === (bool) Tools::isSubmit('log')) {
            $logs = [
                'PageNotFound' => self::LOG_PAGE_NOT_FOUND,
                'Firewall' => self::LOG_FIREWALL,
                'BruteForce' => self::LOG_BRUTE_FORCE,
                'MalwareScan' => self::LOG_MALWARE_SCAN,
                'FileChanges' => self::LOG_FILE_CHANGES,
                'Cronjob' => self::LOG_CRONJOB,
            ];

            foreach ($logs as $key => $log) {
                if ($key === Tools::getValue('log')) {
                    // Clear
                    if ('1' === Tools::getValue('clear_log')) {
                        $out[] = $this->displayConfirmation($this->l('File') . ' <strong>' . $log . '</strong> ' . $this->l('has been cleared.'));
                        \file_put_contents($this->getLogFile($log), '');
                    }

                    // Download
                    if ('1' === Tools::getValue('download_log')) {
                        \clearstatcache();
                        if (0 === \filesize($this->getLogFile($log))) {
                            $out[] = $this->displayConfirmation($this->l('File') . ' <strong>' . $log . '</strong> ' . $this->l('is empty. Nothing to download.'));
                        } else {
                            $this->downloadFile($this->getLogFile($log));
                        }
                    }
                }
            }
        }

        // Btn: Port Scanner
        if (true === (bool) Tools::isSubmit('PortScannerAnalyze')) {
            $this->portScanner();

            $portScannerReportPath = _PS_MODULE_DIR_ . self::REPORT_PORT_SCANNER;
            if (\file_exists($portScannerReportPath)) {
                $this->downloadFile($portScannerReportPath, true);
            } else {
                $out[] = $this->displayWarning($this->l('Something went wrong.'));
            }
        }

        // Btn: Port Scanner
        if (true === (bool) Tools::isSubmit('RblCheckerAnalyze')) {
            $serverIp = $_SERVER['SERVER_ADDR'];
            if (empty($serverIp) || '::1' === $serverIp || '127.0.0.1' === $serverIp) {
                $out[] = $this->displayWarning($this->l('You cannot generate this report while you are on localhost.'));
            } else {
                $this->generateReportRbl();

                $rblCheckerReportPath = _PS_MODULE_DIR_ . self::REPORT_RBL_CHECKER;
                if (\file_exists($rblCheckerReportPath)) {
                    $this->downloadFile($rblCheckerReportPath, true);
                } else {
                    $out[] = $this->displayWarning($this->l('Something went wrong.'));
                }
            }
        }

        // Validate input: Permissions
        if (true === (bool) Tools::isSubmit('PermissionsAnalyze')) {
            if (true === $this->isWindowsOs()) {
                $out[] = $this->displayConfirmation($this->l('Windows is not using file permissions. Nothing to fix!'));
            } else {
                $permissionsReportPath = _PS_MODULE_DIR_ . self::REPORT_PERMISSIONS;

                $this->chmodFileFolderAnalyze(_PS_ROOT_DIR_ . \DIRECTORY_SEPARATOR);

                // Delete file if empty
                \clearstatcache();
                if (0 === \filesize($permissionsReportPath)) {
                    Tools::deleteFile($permissionsReportPath);
                }

                // Download
                if (\file_exists($permissionsReportPath)) {
                    $this->downloadFile($permissionsReportPath, true);
                } else {
                    $out[] = $this->displayConfirmation($this->l('The report is empty. Everything is good!'));
                }
            }
        }

        // Validate and create Index
        if (true === (bool) Tools::isSubmit('CreateIndexAnalyze')) {
            $dirsIndex = [
                _PS_MODULE_DIR_,
                _PS_ALL_THEMES_DIR_,
            ];

            foreach ($dirsIndex as $dirIndex) {
                $this->addIndexRecursively($dirIndex, true);
            }

            $createIndexPath = _PS_MODULE_DIR_ . self::REPORT_CREATE_INDEX;

            if (\file_exists($createIndexPath)) {
                $this->downloadFile($createIndexPath, true);
            } else {
                $out[] = $this->displayConfirmation($this->l('The report is empty. Everything is good!'));
            }
        }

        // Submit save
        if (true === (bool) Tools::isSubmit('SubmitSecurityLiteModule')) {
            $this->postProcess();

            $out[] = $this->displayConfirmation($this->l('Settings updated!'));
        }

        if ((int) Configuration::get('LITE_DELETE_OLD_CARTS_DAYS') < 2) {
            Configuration::updateValue('LITE_DELETE_OLD_CARTS_DAYS', 2);
        }

        // Validate IP activated setting
        if (false === (bool) Configuration::get('LITE_BAN_IP')) {
            Configuration::updateValue('LITE_BAN_IP_ACTIVATE', 0);
        }

        // Validate UA activated setting
        if (false === (bool) Configuration::get('LITE_BLOCK_USER_AGENT')) {
            Configuration::updateValue('LITE_BLOCK_USER_AGENT_ACTIVATE', 0);
        }

        // Validate IP addresses
        $fieldIps = [
            'LITE_BAN_IP',
            'LITE_FIREWALL_WHITELIST',
            'LITE_WHITELIST_IPS',
            'LITE_WHITELIST_PROTECT_CONTENT',
        ];

        foreach ($fieldIps as $fieldIp) {
            $this->validateIps($fieldIp);
        }

        // Validate user agents and other lists
        $fieldStrings = [
            'LITE_BLOCK_USER_AGENT',
        ];

        foreach ($fieldStrings as $fieldString) {
            $this->validateCommaSeparatedString($fieldString);
        }

        if (true === (bool) Tools::isSubmit('RemoveFilesAnalyze')) {
            $elements = \array_merge($this->getFilesRoot(), $this->checkFilesCVE20179841(), $this->getFilePathExt(_PS_MODULE_DIR_), $this->getFilePathExt(_PS_ROOT_DIR_));
            if (!empty($elements)) {
                $reportPath = _PS_MODULE_DIR_ . self::REPORT_REMOVE_FILES;
                \file_put_contents($reportPath, \implode(\PHP_EOL, $elements), \FILE_APPEND | \LOCK_EX);

                $this->downloadFile($reportPath, true);
            } else {
                $out[] = $this->displayConfirmation($this->l('The report is empty. Everything is good!'));
            }
        }

        Configuration::updateValue('LITE_ADMIN_DIRECTORY_NAME', \basename(_PS_ADMIN_DIR_));

        // Empty password
        Configuration::updateValue('LITE_PASSWORD_GENERATOR', null);

        $out[] = $this->displayInformation($this->l('You are using Security Lite. Some features are locked in this version. To unlock all features, you must upgrade to Security Pro. You can buy it here') . ': ' . $this->generateLink('https://addons.prestashop.com/en/website-security-access/44413-security-pro-all-in-one.html', 'https://addons.prestashop.com/en/website-security-access/44413-security-pro-all-in-one.html'));

        // Load JS
        $this->context->controller->addJS($this->_path . 'views/js/menu.js');
        $this->context->controller->addJS($this->_path . 'views/js/secure-random-password.js');

        // Reset URL
        $url = $this->getAdminLink('AdminModules', true) . '&configure=securitylite';
        $parseUrl = \parse_url($url);
        $parseUrlPath = $parseUrl['path'];
        $parseUrlQuery = $parseUrl['query'];
        $finalUrl = $parseUrlPath . '?' . $parseUrlQuery;
        $resetUrl = '<script>window.history.replaceState({}, document.title, "' . $finalUrl . '");</script>';

        // Return the output
        return \implode('', $out) . $this->renderForm() . $resetUrl;
    }

    /**
     * Hook stuff in front office header.
     *
     * @param array $params
     *
     * @return string
     */
    public function hookDisplayHeader($params)
    {
        // Disable browser features with javascript
        $this->protectContent();

        // Load firewall rules
        $this->getFirewall();

        // Disable contact form
        if (true === (bool) Configuration::get('LITE_DISABLE_CONTACT_FORM')) {
            if ($this->context->controller instanceof ContactController) {
                \Tools::redirect('pagenotfound');
            }
            $this->context->controller->addCSS($this->_path . '/views/css/disable-contact-form.css');
        }

        $out = [];

        return \implode('', $out);
    }

    /**
     * Hook stuff in back office header.
     *
     * @param array $params
     */
    public function hookDisplayBackOfficeTop($params)
    {
        // Menu icon on PrestaShop 1.6
        $this->context->controller->addCss($this->_path . 'views/css/menuTabIcon.css');
    }

    /**
     * Install tab.
     *
     * @return bool
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
        $tab->class_name = 'Adminsecuritylite';

        if (Tools::version_compare(_PS_VERSION_, '1.7.0.0', '>=')) {
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
     *
     * @return bool
     */
    public function uninstallTab()
    {
        $tabId = (int) Tab::getIdFromClassName('Adminsecuritylite');
        if (!$tabId) {
            return true;
        }

        $tab = new Tab($tabId);

        return $tab->delete();
    }

    /**
     * Creates a new backup file. Return true on successful backup.
     *
     * @return bool
     */
    public function backupDatabase()
    {
        if (false === (bool) Configuration::get('LITE_BACKUP_DB')) {
            return false;
        }

        $ignoreInsertTable = [
            _DB_PREFIX_ . 'connections',
            _DB_PREFIX_ . 'connections_page',
            _DB_PREFIX_ . 'connections_source',
            _DB_PREFIX_ . 'guest',
            _DB_PREFIX_ . 'statssearch',
        ];

        // Generate some random number, to make it extra hard to guess backup file names
        $rand = Tools::strtolower(Tools::passwdGen(16));
        $date = \time();

        $backupFile = _PS_MODULE_DIR_ . $this->name . self::DIR_BACKUP_DATABASE . $date . '-' . $rand . '.sql';

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

        \fwrite($fp, '/* Backup for ' . $this->getBaseURL() . \PHP_EOL . ' *  at ' . \date('Y-m-d', $date) . \PHP_EOL . ' */' . \PHP_EOL);
        \fwrite($fp, \PHP_EOL . 'SET NAMES \'utf8\';');
        \fwrite($fp, \PHP_EOL . 'SET FOREIGN_KEY_CHECKS = 0;');
        \fwrite($fp, \PHP_EOL . 'SET SESSION sql_mode = \'\';' . \PHP_EOL . \PHP_EOL);

        // Find all tables
        $tables = Db::getInstance()->executeS('SHOW TABLES');
        $found = 0;
        foreach ($tables as $table) {
            $table = \current($table);

            // Skip tables which don\'t start with _DB_PREFIX_
            if (\Tools::strlen($table) < \Tools::strlen(_DB_PREFIX_) || 0 !== \strncmp($table, _DB_PREFIX_, \Tools::strlen(_DB_PREFIX_))) {
                continue;
            }

            // Export the table schema
            $schema = Db::getInstance()->executeS('SHOW CREATE TABLE `' . $table . '`');

            if (1 !== \count($schema) || !isset($schema[0]['Table']) || !isset($schema[0]['Create Table'])) {
                \fclose($fp);

                return false;
            }

            \fwrite($fp, '/* Scheme for table ' . $schema[0]['Table'] . ' */' . \PHP_EOL);

            \fwrite($fp, $schema[0]['Create Table'] . ';' . \PHP_EOL . \PHP_EOL);

            if (!\in_array($schema[0]['Table'], $ignoreInsertTable, true)) {
                $data = Db::getInstance()->query('SELECT * FROM `' . $schema[0]['Table'] . '`', false);
                $sizeof = Db::getInstance()->numRows();
                $lines = \explode(\PHP_EOL, $schema[0]['Create Table']);

                if ($data && $sizeof > 0) {
                    // Export the table data
                    \fwrite($fp, 'INSERT INTO `' . $schema[0]['Table'] . '` VALUES' . \PHP_EOL);
                    $i = 1;
                    while ($row = Db::getInstance()->nextRow($data)) {
                        $s = '(';

                        foreach ($row as $field => $value) {
                            $tmp = '\'' . pSQL($value, true) . '\',';
                            if ('\'\',' !== $tmp) {
                                $s .= $tmp;
                            } else {
                                foreach ($lines as $line) {
                                    if (false !== \mb_strpos($line, '`' . $field . '`')) {
                                        if (\preg_match('/(.*NOT NULL.*)/Ui', $line)) {
                                            $s .= '\'\',';
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
                            $s .= ');' . \PHP_EOL . 'INSERT INTO `' . $schema[0]['Table'] . '` VALUES' . \PHP_EOL;
                        } elseif ($i < $sizeof) {
                            $s .= '),' . \PHP_EOL;
                        } else {
                            $s .= ');' . \PHP_EOL;
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
            $this->deleteOldBackups($backupSaved, self::DIR_BACKUP_DATABASE);
        }

        return true;
    }

    /**
     * Delete old carts.
     */
    public function deleteOldCarts()
    {
        if (Configuration::get('LITE_DELETE_OLD_CARTS')) {
            $query = 'DELETE FROM `' . _DB_PREFIX_ . 'cart`
            WHERE id_cart NOT IN (SELECT id_cart FROM `' . _DB_PREFIX_ . 'orders`)
            AND date_add < "' . pSQL(\date('Y-m-d', \strtotime('-' . Configuration::get('LITE_DELETE_OLD_CARTS_DAYS') . ' day'))) . '"';

            Db::getInstance()->Execute($query);
        }
    }

    /**
     * Encrypt data.
     *
     * @param string $data
     */
    public function encrypt($data)
    {
        if (Tools::version_compare(_PS_VERSION_, '1.7.0.0', '>=')) {
            return Tools::hashIV($data); // PS 1.7
        }

        return Tools::encryptIV($data); // PS 1.6
    }

    /**
     * Log cronjobs.
     *
     * @param string $name
     * @param string $response
     */
    public function logCron($name, $response)
    {
        $data = [];
        $data[] = '[' . \date('Y-m-d H:i:s') . ']';
        $data[] = '[' . $name . ']';
        $data[] = $this->l('Response') . ': "' . $response . '"';
        \file_put_contents($this->getLogFile(self::LOG_CRONJOB), \implode(' ', $data) . \PHP_EOL, \FILE_APPEND);
    }

    /**
     * Remove generated content from .htaccess file.
     */
    public function removeHtaccessContent()
    {
        Tools::deleteFile(_PS_ROOT_DIR_ . \DIRECTORY_SEPARATOR . '.htpasswd');
        $path = _PS_ADMIN_DIR_ . \DIRECTORY_SEPARATOR . '.htaccess';

        if (!\file_exists($path)) {
            return;
        }

        $htaccessContent = \Tools::file_get_contents($path);

        if (\preg_match('/\# ~security_pro~(.*?)\# ~security_LITE_end~/s', $htaccessContent, $m)) {
            $contentToRemove = $m[0];
            $htaccessContent = \str_replace($contentToRemove, '', $htaccessContent);
        }
        \file_put_contents($path, $htaccessContent);

        if (0 === \filesize($path)) {
            Tools::deleteFile($path);
        }
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
        $helper->submit_action = 'SubmitSecurityLiteModule';
        $helper->currentIndex = $this->getAdminLink('AdminModules', false) . '&configure=securitylite&tab_module=' . $this->tab;
        $helper->token = \Tools::getAdminTokenLite('AdminModules');
        $helper->tpl_vars = [
            'fields_value' => $this->getConfigFormValues(),
            'languages' => $this->context->controller->getLanguages(),
            'id_language' => $this->context->language->id,
        ];

        $dashboard = [
            $this->fieldsFormDashboard(),
        ];

        $generalSettings = [
            $this->fieldsFormGeneralSettings(),
        ];

        $loginProtection = [
            $this->fieldsFormBruteForceProtection(),
            $this->fieldsFormTwoFactorAuth(),
            $this->fieldsFormSecondLogin(),
            $this->fieldsFormAdminStealthLogin(),
        ];

        $passwordstrength = [
            $this->fieldsFormPasswordStrengh(),
        ];

        $httpHeaders = [
            $this->fieldsFormHttpSecurityHeaders(),
        ];

        $firewall = [
            $this->fieldsFormFirewall(),
            $this->fieldsFormAntiSpam(),
        ];

        $malwareScanner = [
            $this->fieldsFormMalwareScan(),
        ];

        $cartProtection = [
            $this->fieldsFormAntiFakeCarts(),
        ];

        $montoring = [
            $this->fieldsFormWebsiteMonitoringService(),
            $this->fieldsFormMonitoringChanges(),
        ];

        $antiFraud = [
            $this->fieldsFormAntiFraud(),
        ];

        $contentProtection = [
            $this->fieldsFormProtectContent(),
        ];

        $backup = [
            $this->fieldsFormBackup(),
        ];

        $tools = [
            $this->fieldsFormAdminDir(),
            $this->fieldsFormTools(),
            $this->fieldsFormPasswdGen(),
        ];

        $analysis = [
            $this->fieldsFormAnalyzeSystem(),
            $this->fieldsFormAnalyzeServerConfig(),
            $this->fieldsFormAnalyzeSsl(),
            $this->fieldsFormAnalyzeModules(),
        ];

        $maintenance = [
            $this->fieldsFormMaintenanceMode(),
        ];

        $help = [
            $this->fieldsFormAutoConfig(),
            $this->fieldsFormHelp(),
        ];

        $displayForms = \array_merge($dashboard, $generalSettings, $loginProtection, $httpHeaders, $passwordstrength, $firewall, $malwareScanner, $cartProtection, $montoring, $antiFraud, $contentProtection, $backup, $tools, $analysis, $maintenance, $help);

        return $helper->generateForm($displayForms);
    }

    /**
     * @return array
     */
    protected function fieldsFormAdminDir()
    {
        return [
            'form' => [
                'legend' => [
                    'title' => $this->l('Admin Folder'),
                    'icon' => 'icon-folder-o',
                ],
                'description' => $this->l('You should always keep the path to your admin login secret. If you need to change it, you can change it with this tool.'),
                'input' => [
                    [
                        'type' => 'switch',
                        'col' => 8,
                        'label' => $this->l('Are you sure, you want to change the name of your admin folder?'),
                        'name' => 'LITE_ADMIN_DIRECTORY',
                        'is_bool' => true,
                        'disabled' => true,
                        'desc' => $this->proFeature . $this->l('You will be redirected to the new URL once you click') . ' \'' . $this->l('Save') . '\' ' . $this->l('if this option is set to') . ' \'' . $this->l('Yes') . '\'.',
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
                        'col' => 6,
                        'type' => 'text',
                        'prefix' => $this->getBaseURL(),
                        'disabled' => true,
                        'desc' => $this->proFeature . $this->l('Your admin folder name should include both letters and numbers. Make it hard to guess; don\'t use something like admin123, administrator, back office, etc.') . ' <a onclick="" href="javascript:void(0)">' . $this->l('Generate a secure folder name') . '</a>.',
                        'name' => 'LITE_ADMIN_DIRECTORY_NAME',
                        'label' => $this->l('Directory name'),
                        'hint' => $this->l('Accepted characters') . ': \'a-z A-Z 0-9 _ . -\'',
                    ],
                ],
                'submit' => [
                    'title' => $this->l('Save'),
                ],
            ],
        ];
    }

    /**
     * @return array
     */
    protected function fieldsFormGeneralSettings()
    {
        $dropboxToken = [
            $this->l('Log on to your Dropbox account.'),
            $this->l('Access') . ' ' . $this->generateLink('https://www.dropbox.com/developers/apps/create') . ' ' . $this->l('from your browser.'),
            $this->l('Choose Dropbox Legacy API on the first step.'),
            $this->l('Choose App folder access on the second step.'),
            $this->l('Give your App a name. That name will become a folder in your Dropbox account.'),
            $this->l('Click the \'Create App\' button.'),
            $this->l('Scroll down to the \'OAuth 2\' block and hit the \'Generate\' button near the \'Generated access token\' text.'),
            $this->l('After the token is generated, you\'ll see a string of letters and numbers. This is your Dropbox API access token. You should now copy this token into the field above.'),
        ];

        $googleApiV2 = [
            $this->l('Log on to your Google account.'),
            $this->l('Access') . ' ' . $this->generateLink('https://www.google.com/recaptcha/admin/create') . ' ' . $this->l('from your browser.'),
            $this->l('Select the reCAPTCHA v2 radio button.'),
            $this->l('Register your domain.'),
            $this->l('Copy your Site key and your Secret key into the fields above.'),
        ];

        $googleApiV3 = [
            $this->l('Log on to your Google account.'),
            $this->l('Access') . ' ' . $this->generateLink('https://www.google.com/recaptcha/admin/create') . ' ' . $this->l('from your browser.'),
            $this->l('Select the reCAPTCHA v3 radio button.'),
            $this->l('Register your domain.'),
            $this->l('Copy your Site key and your Secret key into the fields above.'),
        ];

        $googleSafeBrowsingApiV4 = [
            $this->l('Log on to your Google account.'),
            $this->l('Access') . ' ' . $this->generateLink('https://console.developers.google.com/apis/library/safebrowsing.googleapis.com') . ' ' . $this->l('from your browser.'),
            $this->l('Enable Safe Browsing API.'),
            $this->l('Select a project or create a new one.'),
            $this->l('Click Credentials.'),
            $this->l('Click Create credentials.'),
            $this->l('Copy your API key into the field above.'),
        ];

        $honeypotApi = [
            $this->l('Log on to your Honeypot Project account.'),
            $this->l('Access') . ' ' . $this->generateLink('https://www.projecthoneypot.org/account_login.php') . ' ' . $this->l('from your browser.'),
            $this->l('Your API key is found on the top left of your Project Honey Pot Dashboard. It will be the first line under \'Your Stats\'.'),
            $this->l('Copy your Honeypot API key into the field above.'),
        ];

        $montasticApi = [
            $this->l('Log on to your Montastic account.'),
            $this->l('Access') . ' ' . $this->generateLink('https://montastic.com/me?tab=form_profile') . ' ' . $this->l('from your browser.'),
            $this->l('Copy your REST API key into the field above.'),
        ];

        $timeZoneLink = $this->getAdminLink('AdminLocalization', true);

        $timeZoneText = $this->l('As some of the features in this module are based on time, it is very important that you have chosen the correct time zone. Your current chosen time zone is') . ' <strong>' . Configuration::get('PS_TIMEZONE') . '</strong>. ' . $this->generateLink($timeZoneLink, $this->l('Change the time zone')) . '.';

        if (false === \function_exists('mail')) {
            $errorMessage = $this->l('PHP mail function is disabled on your system. You must PHP mail function to use the mail notification features.');
        } else {
            $errorMessage = null;
        }

        return [
            'form' => [
                'legend' => [
                    'title' => $this->l('General Settings'),
                    'icon' => 'icon-cog',
                ],
                'description' => $this->l('Some features in this module use external free services (no paid subscription is required for any of the services). To use these features, you must get an API key/token from the services.') . '<br>' . $timeZoneText,
                'warning' => $this->l('Please save the following link to a safe place') . ': ' . $this->generateUnlockLink() . '<br>' . $this->l('Running this link will disable brute force protection, two-factor authentication and admin stealth login. This link can be used for when you get locked out from your back office.'),
                'error' => $errorMessage,
                'input' => [
                    [
                        'col' => 8,
                        'type' => 'text',
                        'desc' => $this->proFeature . '</p><ol class="help-block"><li>' . \implode('</li><li>', $dropboxToken) . '</li></ol><p>',
                        'name' => 'LITE_BACKUP_DB_TOKEN',
                        'label' => $this->l('Dropbox access token'),
                        'prefix' => '<i class="icon-dropbox"></i>',
                        'hint' => $this->l('Your Dropbox token'),
                        'required' => true,
                        'disabled' => true,
                    ],
                    [
                        'col' => 8,
                        'type' => 'text',
                        'prefix' => '<i class="icon-key"></i>',
                        'name' => 'LITE_FIREWALL_RECAPTCHA_SITE_KEY',
                        'label' => 'Site key (reCAPTCHA v2)',
                        'hint' => $this->l('Your reCAPTCHA v2 site key'),
                        'required' => true,
                    ],
                    [
                        'col' => 8,
                        'type' => 'text',
                        'prefix' => '<i class="icon-key"></i>',
                        'desc' => '</p><ol class="help-block"><li>' . \implode('</li><li>', $googleApiV2) . '</li></ol><p>',
                        'name' => 'LITE_FIREWALL_RECAPTCHA_SECRET',
                        'label' => 'Secret key (reCAPTCHA v2)',
                        'hint' => $this->l('Your reCAPTCHA v2 secret key'),
                        'required' => true,
                    ],
                    [
                        'col' => 8,
                        'type' => 'text',
                        'prefix' => '<i class="icon-key"></i>',
                        'name' => 'LITE_RECAPTCHA_V3_SITE_KEY',
                        'label' => 'Site key (reCAPTCHA v3)',
                        'hint' => $this->l('Your reCAPTCHA v3 site key'),
                        'required' => true,
                        'disabled' => true,
                    ],
                    [
                        'col' => 8,
                        'type' => 'text',
                        'prefix' => '<i class="icon-key"></i>',
                        'desc' => $this->proFeature . '</p><ol class="help-block"><li>' . \implode('</li><li>', $googleApiV3) . '</li></ol><p>',
                        'name' => 'LITE_RECAPTCHA_V3_SECRET',
                        'label' => 'Secret key (reCAPTCHA v3)',
                        'hint' => $this->l('Your reCAPTCHA v3 secret key'),
                        'required' => true,
                        'disabled' => true,
                    ],
                    [
                        'type' => 'select',
                        'label' => $this->l('Display') . ' (reCAPTCHA v3)',
                        'desc' => $this->proFeature . $this->l('Choose where to show the badge.'),
                        'name' => 'LITE_DISPLAY_RECAPTCHA_V3',
                        'disabled' => true,
                        'options' => [
                            'query' => [
                                [
                                    'id_option' => 'bottomleft',
                                    'name' => $this->l('Bottom left'),
                                ],
                                [
                                    'id_option' => 'bottomright',
                                    'name' => $this->l('Bottom right'),
                                ],
                            ],
                            'id' => 'id_option',
                            'name' => 'name',
                        ],
                    ],
                    [
                        'type' => 'select',
                        'label' => $this->l('Theme') . ' (reCAPTCHA v3)',
                        'desc' => $this->proFeature . $this->l('Choose the color theme of the badge.'),
                        'name' => 'LITE_RECAPTCHA_V3_THEME',
                        'disabled' => true,
                        'options' => [
                            'query' => [
                                [
                                    'id_option' => 'light',
                                    'name' => $this->l('Light'),
                                ],
                                [
                                    'id_option' => 'dark',
                                    'name' => $this->l('Dark'),
                                ],
                            ],
                            'id' => 'id_option',
                            'name' => 'name',
                        ],
                    ],
                    [
                        'col' => 8,
                        'type' => 'text',
                        'prefix' => '<i class="icon-key"></i>',
                        'desc' => $this->proFeature . '</p><ol class="help-block"><li>' . \implode('</li><li>', $googleSafeBrowsingApiV4) . '</li></ol><p>',
                        'name' => 'LITE_GOOGLE_SAFE_BROWSING_V4_API',
                        'label' => 'Google Safe Browsing v4',
                        'hint' => $this->l('Your Google Safe Browsing v4 API key'),
                        'required' => true,
                        'disabled' => true,
                    ],
                    [
                        'col' => 8,
                        'type' => 'text',
                        'prefix' => '<i class="icon-key"></i>',
                        'desc' => $this->proFeature . '</p><ol class="help-block"><li>' . \implode('</li><li>', $honeypotApi) . '</li></ol><p>',
                        'name' => 'LITE_HONEYPOT_API',
                        'label' => $this->l('Honeypot API'),
                        'hint' => $this->l('Access keys are 12-alpha characters (no numbers). They are lower-case.'),
                        'required' => true,
                        'disabled' => true,
                    ],
                    [
                        'col' => 8,
                        'type' => 'text',
                        'prefix' => '<i class="icon-key"></i>',
                        'desc' => '</p><ol class="help-block"><li>' . \implode('</li><li>', $montasticApi) . '</li></ol><p>',
                        'name' => 'LITE_MONTASTIC_API',
                        'label' => 'Montastic API',
                        'hint' => $this->l('Access keys are 40 characters.'),
                        'required' => true,
                    ],
                    [
                        'col' => 8,
                        'type' => 'text',
                        'desc' => $this->proFeature . $this->l('You can enable e-mail notifications on some of the features. To use these features, you must enter your e-mail in the above field.'),
                        'name' => 'LITE_GENERAL_EMAIL',
                        'prefix' => '<i class="icon-envelope-o"></i>',
                        'label' => $this->l('E-mail'),
                        'hint' => $this->l('Must be a valid e-mail address'),
                        'required' => true,
                        'disabled' => true,
                    ],
                    [
                        'type' => 'switch',
                        'col' => 8,
                        'label' => $this->l('Debug cronjobs'),
                        'name' => 'LITE_DEBUG_CRON',
                        'is_bool' => true,
                        'desc' => $this->l('If one of your cronjobs fails, you can enable this option to find the problem. Run your cronjob manually in your browser to see the error.'),
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

    /**
     * Display form for monitoring changes.
     *
     * @return array
     */
    protected function fieldsFormMonitoringChanges()
    {
        return [
            'form' => [
                'legend' => [
                    'title' => $this->l('Change Monitoring'),
                    'icon' => 'icon-bell-o',
                ],
                'description' => $this->l('If you can\'t monitor changes, you can\'t manage them. To control your environment, you need the ability to analyze and respond to changes. The module allows you to monitor some important changes like file changes.'),
                'input' => [
                    [
                        'type' => 'switch',
                        'col' => 8,
                        'label' => $this->l('Get an e-mail if file changes'),
                        'name' => 'LITE_FILE_CHANGES_EMAIL',
                        'is_bool' => true,
                        'disabled' => true,
                        'desc' => $this->proFeature . $this->l('Track every file change on your server and let you know by e-mail if something has changed.') . ' ' . $this->l('The module also does reports file changes during PrestaShop update, module update, theme update, etc.') . ' ' . $this->l('Once this option is enabled, a cronjob will appear in your dashboard that you need to set up.'),
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
                        'col' => 8,
                        'label' => $this->l('Log file changes'),
                        'name' => 'LITE_FILE_CHANGES_LOG',
                        'is_bool' => true,
                        'disabled' => true,
                        'desc' => $this->proFeature . $this->l('Track every file change on your server and log it if something has changed.') . ' ' . $this->l('The module does also reports file changes during PrestaShop update, module update, theme update, etc.') . ' ' . $this->l('The log can be found on your dashboard.'),
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
                        'type' => 'textarea',
                        'col' => 8,
                        'disabled' => true,
                        'desc' => $this->proFeature . $this->l('Whitelists dynamic files') . '. ' . $this->l('Separate files by a comma') . ' (\',\') ' . $this->l('without space.'),
                        'name' => 'LITE_FILE_CHANGES_WHITELIST',
                        'label' => $this->l('Whitelist filter for file changes'),
                        'hint' => $this->l('E.g.') . ' file.json,file.xml',
                    ],
                    [
                        'type' => 'switch',
                        'col' => 8,
                        'label' => $this->l('Get an e-mail if server IP changes'),
                        'name' => 'LITE_SERVER_IP',
                        'is_bool' => true,
                        'disabled' => true,
                        'desc' => $this->proFeature . $this->l('Get notified if the server IP changes.') . ' ' . $this->l('Once this option is enabled, a cronjob will appear in your dashboard that you need to set up.'),
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
                        'col' => 8,
                        'label' => $this->l('Get an e-mail if the country of the server changes'),
                        'name' => 'LITE_SERVER_LOCATION',
                        'is_bool' => true,
                        'disabled' => true,
                        'desc' => $this->proFeature . $this->l('Get notified if the location of the server country changes.') . ' ' . $this->l('Once this option is enabled, a cronjob will appear in your dashboard that you need to set up.'),
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
                        'col' => 8,
                        'label' => $this->l('Get an e-mail if your ISP changes'),
                        'name' => 'LITE_SERVER_ISP',
                        'is_bool' => true,
                        'disabled' => true,
                        'desc' => $this->proFeature . $this->l('Get notified if the name of your ISP changes.') . ' ' . $this->l('Once this option is enabled, a cronjob will appear in your dashboard that you need to set up.'),
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
                        'col' => 8,
                        'label' => $this->l('Get an e-mail if your domain is about to expire'),
                        'name' => 'LITE_DOMAIN_EXPIRE',
                        'is_bool' => true,
                        'disabled' => true,
                        'desc' => $this->proFeature . $this->l('Get notified if your domain is about to expire.') . ' ' . $this->l('Once this option is enabled, a cronjob will appear in your dashboard that you need to set up.'),
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
                        'col' => 8,
                        'label' => $this->l('Get an e-mail if your TLS certificate is about to expire'),
                        'name' => 'LITE_TLS_EXPIRE',
                        'disabled' => true,
                        'is_bool' => true,
                        'desc' => $this->proFeature . $this->l('Get notified if your TLS certificate is about to expire.') . ' ' . $this->l('Once this option is enabled, a cronjob will appear in your dashboard that you need to set up.'),
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

    /**
     * Display dashboard.
     *
     * @return array
     */
    protected function fieldsFormDashboard()
    {
        $cronJobs = [];
        $link = '<i class="icon icon-link"></i> ' . $this->l('Run cronjob');

        // Cronjobs
        if (true === (bool) Configuration::get('LITE_FILE_CHANGES_EMAIL')
            || true === (bool) Configuration::get('LITE_FILE_CHANGES_LOG')
            || true === (bool) Configuration::get('LITE_SERVER_IP')
            || true === (bool) Configuration::get('LITE_SERVER_LOCATION')
            || true === (bool) Configuration::get('LITE_SERVER_ISP')
            || true === (bool) Configuration::get('LITE_DOMAIN_EXPIRE')
            || true === (bool) Configuration::get('LITE_TLS_EXPIRE')
            ) {
            $cronJobs[] = [
                $this->l('Title') => $this->l('Monitoring'),
                $this->l('Cronjob') => '<kbd>' . $this->generateCronLink('Monitoring') . '</kbd>',
                null => '<span class="securitylite-position">' . $this->generateBtnLink($link, $this->generateCronLink('Monitoring', true)) . '</span>',
            ];
        }

        // Validate input: Database backup
        if (true === (bool) Configuration::get('LITE_BACKUP_DB')) {
            $cronJobs[] = [
                $this->l('Title') => $this->l('Backup database'),
                $this->l('Cronjob') => '<kbd>' . $this->generateCronLink('BackupDatabase') . '</kbd>',
                null => '<span class="securitylite-position">' . $this->generateBtnLink($link, $this->generateCronLink('BackupDatabase', true)) . '</span>',
            ];
        }

        $backupDir = _PS_MODULE_DIR_ . 'securitylite/backup';
        if (!\is_dir($backupDir . '/database/')) {
            \mkdir($backupDir . '/database/', 0755, true);
            $this->addIndexRecursively($backupDir);
            \file_put_contents($backupDir . '/.htaccess', $this->getHtaccessContent());
        }

        $ext = [
            'bz2',
            'gz',
            'zip',
        ];

        $fileBackupTotal = [
            [
                self::DIR_BACKUP_DATABASE,
                'BackupDatabaseDownload',
                'BackupDatabaseDelete',
                $this->l('Database'),
            ],
        ];

        $localBackup = [];
        foreach ($fileBackupTotal as $fileBackupSingle) {
            if ($handle = \opendir(_PS_MODULE_DIR_ . $this->name . $fileBackupSingle[0])) {
                while (false !== ($entry = \readdir($handle))) {
                    if ('.' !== $entry && '..' !== $entry) {
                        if (\in_array(\pathinfo(\basename($entry), \PATHINFO_EXTENSION), $ext, true)) {
                            $pathToFile = \realpath(_PS_MODULE_DIR_ . $this->name . $fileBackupSingle[0] . $entry);
                            $date = \date('Y-m-d', \Tools::substr(\basename($entry), 0, 10));
                            $localBackup[] = [
                                $this->l('Type') => $fileBackupSingle[3],
                                $this->l('Size') => Tools::formatBytes(\filesize($pathToFile), 1) . 'B',
                                $this->l('Date') => $date,
                                $this->l('Path') => $pathToFile,
                                null => '<span class="securitylite-position"><a class="btn btn-default" onclick="return confirm(\'' . $this->l('Are you sure, you want to delete') . ' ' . $entry . '?\')" href="' . $this->currentAdminIndex() . '&' . $fileBackupSingle[2] . '=1&file=' . $entry . '"><i class="icon icon-trash-o"></i> ' . $this->l('Delete') . '</a><span class="securitylite-divider"></span><a class="btn btn-default" href="' . $this->currentAdminIndex() . '&' . $fileBackupSingle[1] . '=1&file=' . $entry . '"><i class="icon icon-download"></i> ' . $this->l('Download') . '</a><span>',
                            ];
                        }
                    }
                }
            }
        }

        $enabled = '<i class="icon icon-check" style="color: ' . self::COLOR_GREEN . '"></i>';
        $disabled = '<i class="icon icon-times" style="color: ' . self::COLOR_RED . '"></i>';

        // Logs
        $logTotal = [
            [
                $this->l('Firewall'),
                self::LOG_FIREWALL,
                'Firewall',
                (true === (bool) Configuration::get('LITE_FIREWALL_LOG')) ? $enabled : $disabled,
            ],
            [
                $this->l('Page not found'),
                self::LOG_PAGE_NOT_FOUND,
                'PageNotFound',
                (true === (bool) Configuration::get('LITE_PAGE_NOT_FOUND_LOG')) ? $enabled : $disabled,
            ],
            [
                $this->l('Malware scan'),
                self::LOG_MALWARE_SCAN,
                'MalwareScan',
                $disabled,
            ],
            [
                $this->l('File changes'),
                self::LOG_FILE_CHANGES,
                'FileChanges',
                $disabled,
            ],
            [
                $this->l('Cronjobs'),
                self::LOG_CRONJOB,
                'Cronjob',
                (!empty($cronJobs)) ? $enabled : $disabled,
            ],
        ];

        $log = [];
        foreach ($logTotal as $logSingle) {
            $log[] = [
                $this->l('Title') => $logSingle[0],
                $this->l('Size') => Tools::formatBytes(\filesize($this->getLogFile($logSingle[1])), 1) . 'B',
                $this->l('Last modified') => \date('Y-m-d', \filemtime($this->getLogFile($logSingle[1]))),
                $this->l('Path') => \realpath($this->getLogFile($logSingle[1])),
                $this->l('Activated') => $logSingle[3],
                null => '<span class="securitylite-position"><a class="btn btn-default" onclick="return confirm(\'' . $this->l('Are you sure, you want to clear') . ' ' . $logSingle[1] . '?\')" href="' . $this->currentAdminIndex() . '&log=' . $logSingle[2] . '&clear_log=1"><i class="icon icon-eraser"></i> ' . $this->l('Clear') . '</a><span class="securitylite-divider"></span><a class="btn btn-default" href="' . $this->currentAdminIndex() . '&log=' . $logSingle[2] . '&download_log=1"><i class="icon icon-download"></i> ' . $this->l('Download') . '</a></span>',
            ];
        }

        $cachePath = _PS_CACHE_DIR_ . 'securitylite';
        $cache = [];
        $cache[] = [
            $this->l('Title') => $this->l('Cache'),
            $this->l('Size') => Tools::formatBytes($this->getDirectorySize([$cachePath]), 1) . 'B',
            $this->l('Description') => $this->l('Clear cache and statistics generated by this module.'),
            null => '<span class="securitylite-position"><a class="btn btn-default" href="' . $this->currentAdminIndex() . '&clear_cache=1"><i class="icon icon-eraser"></i> ' . $this->l('Clear cache') . '</a></span>',
        ];

        $employeeData = $this->getEmployees(false);

        $employee = [];
        foreach ($employeeData as $data) {
            $employee[] = [
                $this->l('Name') => $data['firstname'] . ' ' . $data['lastname'],
                $this->l('E-mail') => $data['email'],
                $this->l('Last password generated') => $data['last_passwd_gen'],
                $this->l('Last connection') => (!empty($data['last_connection_date'])) ? $data['last_connection_date'] : '--',
                $this->l('Activated') => $data['active'] ? $enabled : $disabled,
                null => '<span class="securitylite-position">' . $this->generateBtnLink('<i class="icon icon-pencil"></i> ' . $this->l('Edit'), $this->getEmployeeAdminLink($data['id_employee'])) . '</span>',
            ];
        }

        $out = [];

        $out[] = $this->addHeading($this->l('Logs'), true) . $this->arrayToTable($log);

        $out[] = $this->addHeading($this->l('Employee statistics')) . $this->arrayToTable($employee);

        $outCron = [];
        if (!empty($cronJobs)) {
            $outCron[] = $this->addHeading($this->l('Cronjobs'));

            if (false === (bool) Configuration::get('PS_SHOP_ENABLE')) {
                $outCron[] = $this->addAlertWarning($this->l('Information: You cannot run cronjobs while your shop is in maintenance mode.'));
            }

            $outCron[] = $this->addAlertInfo($this->l('Please set up below cronjobs. It is recommended to run the cronjobs once a day') . ': <kbd>' . \htmlentities('0 3 * * * <' . $this->l('cronjob') . '>') . '</kbd><br>' . $this->l('If your host does not allow you to set up cronjobs, you can use this service instead') . ': ' . $this->generateLink('https://cron-job.org/en/members/jobs/add/') . '<br>' . $this->l('Learn more about cronjobs') . ' ' . $this->generateLink('https://en.wikipedia.org/wiki/Cron', $this->l('here')) . '.');

            $outCron[] = $this->arrayToTable($cronJobs);
        }

        $out[] = \implode('', $outCron);

        if (!empty($localBackup)) {
            $out[] = $this->addHeading($this->l('Local backups')) . $this->arrayToTable($localBackup);
        }

        $out[] = $this->addHeading($this->l('Cache')) . $this->arrayToTable($cache);

        return [
            'form' => [
                'legend' => [
                    'title' => $this->l('Dashboard'),
                    'icon' => 'icon-dashboard',
                ],
                'input' => [
                    [
                        'type' => 'html',
                        'label' => '',
                        'html_content' => \implode('<br>', $out),
                        'col' => 12,
                        'name' => '',
                    ],
                ],
            ],
        ];
    }

    /**
     * Display analyze of system table.
     *
     * @return array
     */
    protected function fieldsFormAnalyzeSystem()
    {
        $checkCves = [
            $this->checkCve202015162(),
            $this->checkCve202015161(),
            $this->checkCve202015160(),
            $this->checkCve202015083(),
            $this->checkCve202015082(),
            $this->checkCve202015081(),
            $this->checkCve202015080(),
            $this->checkCve202015079(),
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
            $this->checkCve20204074(),
            $this->checkCve201913461(),
            $this->checkCve201911876(),
            $this->checkCve20188824(),
            $this->checkCve20188823(),
            $this->checkCve201819355(),
            $this->checkCve201819125(),
            $this->checkCve201819126(),
            $this->checkCve201819124(),
            $this->checkCve201813784(),
            $this->checkCve20187491(),
            $this->checkCve20179841(),
        ];

        $checkSettings = [
            $this->checkPrestaShopVersion(),
            $this->checkPhpVersion(),
            $this->checkTlsEnabled(),
            $this->checkTlsEnabledEverywhere(),
            $this->checkPrestashopToken(),
            $this->checkModSecurity(),
            $this->checkAdminDirectoryName(),
            $this->checkCookieIpAddress(),
            $this->checkPrestashopDevMode(),
        ];

        $check = '<i class="icon icon-check" style="color: ' . self::COLOR_GREEN . '"></i>';
        $vulnerable = '<i class="icon icon-times" style="color: ' . self::COLOR_RED . '"></i>';
        $possible = '<i class="icon icon-question-circle" style="color: ' . self::COLOR_BLUE . '"></i>';
        $good = '--';

        $cveResult = [];
        foreach ($checkCves as $checkCve) {
            (true === $checkCve[1]) ? $nvdNist = $this->getCachedJsonDecodedContent('https://services.nvd.nist.gov/rest/json/cve/1.0/' . $checkCve[0], null, $checkCve[0], 604800)['result']['CVE_Items'][0] : $nvdNist = null;

            $cveResult[] = [
                'CVE' => $this->generateLink('https://nvd.nist.gov/vuln/detail/' . $checkCve[0], $checkCve[0]),
                $this->l('Status') => (true === $checkCve[1]) ? $possible : $check,
                $this->l('Base score') => (true === $checkCve[1]) ? $nvdNist['impact']['baseMetricV3']['cvssV3']['baseScore'] . ' ' . $nvdNist['impact']['baseMetricV3']['cvssV3']['baseSeverity'] : $good,
                $this->l('Description') => (true === $checkCve[1]) ? $nvdNist['cve']['description']['description_data'][0]['value'] : $good,
                $this->l('How to fix') => (true === $checkCve[1]) ? $this->proFeature : $good,
            ];
        }

        $prestaResult = [];
        foreach ($checkSettings as $checkSetting) {
            $prestaResult[] = [
                $this->l('Check') => $checkSetting[0],
                $this->l('Status') => $checkSetting[1] ? $vulnerable : $check,
                $this->l('Description') => $checkSetting[1] ? $checkSetting[3] : $good,
                $this->l('How to fix') => $this->proFeature,
            ];
        }

        $result = $this->addHeading($this->l('Check for insecure PrestaShop settings'), true) . $this->addAlertInfo($this->l('Recommend more secure options for your installation.')) . $this->arrayToTable($prestaResult) . '<br>' . $this->addHeading($this->l('Check for common vulnerabilities and exposures')) . $this->addAlertInfo($this->l('Scan your PrestaShop website for common vulnerabilities and exposures.')) . $this->arrayToTable($cveResult);

        return [
            'form' => [
                'legend' => [
                    'title' => $this->l('Analyze System'),
                    'icon' => 'icon-list',
                ],
                'input' => [
                    [
                        'type' => 'html',
                        'label' => '',
                        'html_content' => $result,
                        'col' => 12,
                        'name' => '',
                    ],
                ],
            ],
        ];
    }

    /**
     * Display form for configuration of maintenance mode.
     *
     * @return array
     */
    protected function fieldsFormMaintenanceMode()
    {
        $maintenanceLink = $this->getAdminLink('AdminMaintenance', true);

        return [
            'form' => [
                'legend' => [
                    'title' => $this->l('Advanced Maintenance Mode'),
                    'icon' => 'icon-wrench',
                ],
                'description' => $this->l('PrestaShop\'s default maintenance mode is very limited. To lower the risk of losing customers while having your shop in maintenance mode, you can use this advanced maintenance mode which is much more user-friendly.') . ' ' . $this->l('If you need to change the text or translate its content, you must do it by PrestaShop\'s translate system.') . ' ' . $this->l('You can enable/disable maintenance mode') . ' ' . $this->generateLink($maintenanceLink, $this->l('here')) . '.',
                'input' => [
                    [
                        'type' => 'switch',
                        'col' => 8,
                        'label' => $this->l('Use advanced maintenance mode'),
                        'name' => 'LITE_ADVANCED_MAINTENANCE_MODE',
                        'is_bool' => true,
                        'desc' => $this->l('This feature does not activate maintenance mode. It does just replace the default maintenance mode with Security Lite\'s advanced maintenance mode.'),
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
                        'col' => 4,
                        'type' => 'text',
                        'prefix' => '<i class="icon-building-o"></i>',
                        'desc' => $this->l('Company name to be displayed.') . ' ' . $this->l('You can leave this field empty if you don\'t want to show this information.'),
                        'name' => 'LITE_ADVANCED_MAINTENANCE_MODE_COMPANY',
                        'label' => $this->l('Company'),
                    ],
                    [
                        'col' => 4,
                        'type' => 'text',
                        'prefix' => '<i class="icon-map-marker"></i>',
                        'desc' => $this->l('Address to be displayed.') . ' ' . $this->l('You can leave this field empty if you don\'t want to show this information.'),
                        'name' => 'LITE_ADVANCED_MAINTENANCE_MODE_ADDRESS',
                        'label' => $this->l('Address'),
                    ],
                    [
                        'col' => 4,
                        'type' => 'text',
                        'prefix' => '<i class="icon-phone"></i>',
                        'desc' => $this->l('The phone number to be displayed.') . ' ' . $this->l('You can leave this field empty if you don\'t want to show this information.'),
                        'name' => 'LITE_ADVANCED_MAINTENANCE_MODE_PHONE',
                        'label' => $this->l('Phone'),
                    ],
                    [
                        'col' => 4,
                        'type' => 'text',
                        'prefix' => '<i class="icon-envelope-o"></i>',
                        'desc' => $this->l('E-mail address to be displayed.') . ' ' . $this->l('You can leave this field empty if you don\'t want to show this information.'),
                        'name' => 'LITE_ADVANCED_MAINTENANCE_MODE_EMAIL',
                        'label' => $this->l('E-mail'),
                    ],
                    [
                        'col' => 4,
                        'type' => 'text',
                        'prefix' => '<i class="icon-facebook"></i>',
                        'desc' => $this->l('Your Facebook page.') . ' ' . $this->l('You can leave this field empty if you don\'t want to show this information.'),
                        'name' => 'LITE_ADVANCED_MAINTENANCE_MODE_FACEBOOK',
                        'label' => 'Facebook',
                    ],
                    [
                        'col' => 4,
                        'type' => 'text',
                        'prefix' => '<i class="icon-twitter"></i>',
                        'desc' => $this->l('Your Twitter profile.') . ' ' . $this->l('You can leave this field empty if you don\'t want to show this information.'),
                        'name' => 'LITE_ADVANCED_MAINTENANCE_MODE_TWITTER',
                        'label' => 'Twitter',
                    ],
                    [
                        'col' => 4,
                        'type' => 'text',
                        'prefix' => '<i class="icon-instagram"></i>',
                        'desc' => $this->l('Your Instagram page.') . ' ' . $this->l('You can leave this field empty if you don\'t want to show this information.'),
                        'name' => 'LITE_ADVANCED_MAINTENANCE_MODE_INSTAGRAM',
                        'label' => 'Instagram',
                    ],
                    [
                        'col' => 4,
                        'type' => 'text',
                        'prefix' => '<i class="icon-pinterest"></i>',
                        'desc' => $this->l('Your Pinterest page.') . ' ' . $this->l('You can leave this field empty if you don\'t want to show this information.'),
                        'name' => 'LITE_ADVANCED_MAINTENANCE_MODE_PINTEREST',
                        'label' => 'Pinterest',
                    ],
                    [
                        'col' => 4,
                        'type' => 'text',
                        'prefix' => '<i class="icon-youtube"></i>',
                        'desc' => $this->l('Your YouTube channel.') . ' ' . $this->l('You can leave this field empty if you don\'t want to show this information.'),
                        'name' => 'LITE_ADVANCED_MAINTENANCE_MODE_YOUTUBE',
                        'label' => 'YouTube',
                    ],
                    [
                        'type' => 'switch',
                        'col' => 8,
                        'label' => $this->l('Show copyright'),
                        'name' => 'LITE_ADVANCED_MAINTENANCE_MODE_COPYRIGHT',
                        'is_bool' => true,
                        'desc' => $this->l('Show copyright at the bottom of the maintenance site.'),
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
                        'col' => 8,
                        'label' => $this->l('Display logo'),
                        'name' => 'LITE_ADVANCED_MAINTENANCE_MODE_LOGO',
                        'is_bool' => true,
                        'desc' => $this->l('Display your logo in the top left corner of the maintenance site.'),
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
                        'col' => 4,
                        'type' => 'text',
                        'desc' => $this->l('Path to the logo that you would like to be displayed.') . ' ' . $this->l('If the field is empty the default logo will be used.'),
                        'name' => 'LITE_ADVANCED_MAINTENANCE_MODE_LOGO_PATH',
                        'label' => $this->l('Logo path'),
                    ],
                ],
                'submit' => [
                    'title' => $this->l('Save'),
                ],
            ],
        ];
    }

    /**
     * Display form for help.
     *
     * @return array
     */
    protected function fieldsFormHelp()
    {
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
        $total = [];
        $total[] = $this->addParagraph($this->l('Thanks for using Security Lite! Questions, issues, or feature requests?'));

        $url = 'https://addons.prestashop.com/' . $trans . '?id_product=44413';
        $total[] = $this->generateBtnLink($this->l('Contact module developer'), $url) . '<br><br>';

        $total[] = $this->addParagraph($this->l('Would you like to translate this module into your language or improve the wording?'));

        $list = [
            $this->l('Click \'Translate\' (flag icon) in the upper right corner.'),
            $this->l('Choose language.'),
            $this->l('Make your changes and save.'),
        ];

        $total[] = '<ol style="font-size: 13px;"><li>' . \implode('</li><li>', $list) . '</li></ol>';

        $total[] = $this->addParagraph($this->l('If you make any improvements to the wording, please export your translation and send it to the module developer, then your improvements will be merged into the next release. Your contribution is appreciated!'));

        $total[] = $this->disabledBtn($this->l('Export translations'));

        return [
            'form' => [
                'legend' => [
                    'title' => $this->l('Help'),
                    'icon' => 'icon-question-circle',
                ],
                'input' => [
                    [
                        'type' => 'html',
                        'label' => '',
                        'html_content' => \implode('', $total),
                        'col' => 12,
                        'name' => '',
                    ],
                ],
            ],
        ];
    }

    /**
     * Display form for help.
     *
     * @return array
     */
    protected function fieldsFormAutoConfig()
    {
        $total = [];

        $total[] = '<script>
$(function() {
    $("#linkTools").click(function(e) {
        e.preventDefault();
        var t = "fieldset_18_18_securitylite";
        $("#" + t).tab("show"), $("#fieldset_25_25_securitylite").removeClass("active"), $("#" + t).addClass("active");
    });
    $("#linkGeneralSettings").click(function(e) {
        e.preventDefault();
        var t = "fieldset_1_1_securitylite";
        $("#" + t).tab("show"), $("#fieldset_25_25_securitylite").removeClass("active"), $("#" + t).addClass("active");
    });
    $("#linkAnalyzeServerConfiguration").click(function(e) {
        e.preventDefault();
        var t = "fieldset_21_21_securitylite";
        $("#" + t).tab("show"), $("#fieldset_25_25_securitylite").removeClass("active"), $("#" + t).addClass("active");
    });
    $("#linkAnalyzeSystem").click(function(e) {
        e.preventDefault();
        var t = "fieldset_20_20_securitylite";
        $("#" + t).tab("show"), $("#fieldset_25_25_securitylite").removeClass("active"), $("#" + t).addClass("active");
    });
    $("#linkAnalyzeModules").click(function(e) {
        e.preventDefault();
        var t = "fieldset_23_23_securitylite";
        $("#" + t).tab("show"), $("#fieldset_25_25_securitylite").removeClass("active"), $("#" + t).addClass("active");
    });
    $("#linkDashboard").click(function(e) {
        e.preventDefault();
        var t = "fieldset_0_securitylite";
        $("#" + t).tab("show"), $("#fieldset_25_25_securitylite").removeClass("active"), $("#" + t).addClass("active");
    });
});
</script>';

        $total[] = $this->addHeading($this->l('Step 1: Configuration of Security Lite'), true);

        $total[] = $this->addParagraph($this->l('It\'s recommended doing a manual configuration of the module. However, if the many features seem overwhelming, you can run a basic auto-configuration of the module. Then you can afterwards fine-tune the settings depending on your needs.'));

        $total[] = $this->addParagraph($this->l('Before we go on it is highly recommended, to add the following keys at') . ' <a id="linkGeneralSettings" href="javascript:void(0)">' . $this->l('General Settings') . '</a>.');

        $list = [
            $this->l('Site key (reCAPTCHA v2)'),
            $this->l('Secret key (reCAPTCHA v2)'),
            $this->l('Honeypot API'),
        ];

        $total[] = '<ol style="font-size: 13px;"><li>' . \implode('</li><li>', $list) . '</li></ol>';

        $total[] = '<div style="color: ' . self::COLOR_RED . ';">' . $this->disabledBtn('<i class="icon icon-cog"></i> ' . $this->l('Run auto-configuration')) . ' ' . $this->addParagraph('<i class="icon icon-exclamation-triangle"></i> ' . $this->l('Running the auto-configuration will change your current settings of Security Lite, so don\'t do it, if you have already configured the module.'), true) . '</div>';

        $total[] = $this->addHeading($this->l('Step 2: Fix vulnerabilities on your system'));

        $total[] = $this->addParagraph($this->l('Go to') . ' <a id="linkTools" href="javascript:void(0)">' . $this->l('Tools') . '</a>. ' . $this->l('There you will find tools to fix insecure file permissions, directory traversal vulnerability, and a tool to delete files that make your shop vulnerable. It is possible to generate a report, to understand what changes the tools will do.'));

        $total[] = $this->addHeading($this->l('Step 3: Analyze your system'));

        $total[] = $this->addParagraph($this->l('Go to') . ' <a id="linkAnalyzeSystem" href="javascript:void(0)">' . $this->l('Analyze System') . '</a> ' . $this->l('and fix as many vulnerabilities as possible.'));

        $total[] = $this->addHeading($this->l('Step 4: Analyze your server configuration'));

        $total[] = $this->addParagraph($this->l('Go to') . ' <a id="linkAnalyzeServerConfiguration" href="javascript:void(0)">' . $this->l('Analyze Server Configuration') . '</a> ' . $this->l('and have a look at the analysis. Here you will see some advanced tips to improve your PHP configuration file. If you are not familiar with this kind of configuration, you can ask your host for help.'));

        $total[] = $this->addHeading($this->l('Step 5: Analyze your modules'));

        $total[] = $this->addParagraph($this->l('Go to') . ' <a id="linkAnalyzeModules" href="javascript:void(0)">' . $this->l('Analyze Modules') . '</a>. ' . $this->l('Here you will see all modules installed in your shop. If you are not using some of the modules, it\'s recommended to uninstall them, especially if those modules are not trusted modules.'));

        $total[] = $this->addHeading($this->l('Step 6: Test your shop'));

        $total[] = $this->addParagraph($this->l('Now test your website to confirm that everything is running:'));

        $test = [
            $this->l('Register a new customer'),
            $this->l('Make a test order'),
            $this->l('Navigate to different products'),
            $this->l('Navigate to different categories'),
        ];

        $total[] = '<ol style="font-size: 13px;"><li>' . \implode('</li><li>', $test) . '</li></ol>';

        $total[] = $this->addHeading($this->l('Step 7: Setup cronjobs'));

        $total[] = $this->addParagraph($this->l('Go to the') . ' <a id="linkDashboard" href="javascript:void(0)">' . $this->l('Dashboard') . '</a>. ' . $this->l('There you will see a section named \'Cronjobs\'. Cronjobs are time-based job scheduler in Unix-like computer operating systems. The cronjobs are used to run features like the malware scanner, the monitoring service, backups, etc. It\'s recommended to set up these cronjobs to run once a day. If you are not familiar with cronjobs, you can ask your host for help.'));

        return [
            'form' => [
                'legend' => [
                    'title' => $this->l('Documentation'),
                    'icon' => 'icon-book',
                ],
                'input' => [
                    [
                        'type' => 'html',
                        'label' => '',
                        'html_content' => \implode('', $total),
                        'col' => 12,
                        'name' => '',
                    ],
                ],
            ],
        ];
    }

    /**
     * @return array
     */
    protected function fieldsFormAnalyzeServerConfig()
    {
        $checkGrids = [
            $this->checkSessionAutoStart(),
            $this->checkSessionUseCookies(),
            $this->checkSessionUseOnlyCookies(),
            $this->checkSessionCookieHttponly(),
            $this->checkPhpUseTransSid(),
            $this->checkCookieSecure(),
            $this->checkUseScrickMode(),
            $this->checkCookieLifetime(),
            $this->checkLazyWrite(),
            $this->checkSidLength(),
            $this->checkSessionGcProbability(),
            $this->checkSessionGcDivisor(),
            $this->checkSidBitsPerCharacter(),
            $this->checkUrlFopen(),
            $this->checkUrlInclude(),
            $this->checkDisplayErrors(),
            $this->checkLogErrors(),
            $this->checkErrorReporting(),
            $this->checkDisplayStartupErrors(),
            $this->checkExposePhp(),
            $this->checkRegisterArgcArgv(),
            $this->checkShortOpenTag(),
            $this->checkFileUploads(),
            $this->checkUploadMaxFileSize(),
            $this->checkPostMaxSize(),
            $this->checkMaxInputVars(),
            $this->checkMaxInputTime(),
            $this->checkMemoryLimit(),
            $this->checkMaxExecutionTime(),
            $this->checkDefaultCharset(),
        ];

        $check = '<i class="icon icon-check" style="color: ' . self::COLOR_GREEN . '"></i>';
        $vulnerable = '<i class="icon icon-times" style="color: ' . self::COLOR_RED . '"></i>';
        $good = '--';

        $result = [];
        foreach ($checkGrids as $checkGrid) {
            $result[] = [
                $this->l('Key') => $checkGrid[0],
                $this->l('Current') => $checkGrid[1],
                $this->l('Recommended') => $this->proFeature,
                $this->l('Status') => $checkGrid[3] ? $vulnerable : $check,
                $this->l('Description') => $checkGrid[3] ? $checkGrid[4] : $good,
            ];
        }

        return [
            'form' => [
                'legend' => [
                    'title' => $this->l('Analyze Server Configuration'),
                    'icon' => 'icon-list',
                ],
                'description' => $this->l('Here are some advanced tips to secure your PHP configuration file. Your PHP configuration file is named php.ini. This file could be stored in different locations according to your setup. If you are not familiar with php.ini, you can ask your host for help.') . '<br>' . $this->l('According to your system, the loaded php.ini file is located here') . ': <strong>' . \php_ini_loaded_file() . '</strong>, ' . $this->l('but keep in mind that this php.ini file could be overridden somewhere, depending on your setup.'),
                'input' => [
                    [
                        'type' => 'html',
                        'label' => '',
                        'html_content' => $this->arrayToTable($result),
                        'col' => 12,
                        'name' => '',
                    ],
                ],
            ],
        ];
    }

    /**
     * @return array
     */
    protected function fieldsFormAnalyzeSsl()
    {
        $url = 'https://www.howsmyssl.com/a/check';

        $ssl = $this->getCertInfo();

        $data = $this->getCachedJsonDecodedContent($url, null, 'certificate', 604800);

        $check = '<i class="icon icon-check" style="color: ' . self::COLOR_GREEN . '"></i>';
        $vulnerable = '<i class="icon icon-times" style="color: ' . self::COLOR_RED . '"></i>';
        $possible = '<i class="icon icon-question-circle" style="color: ' . self::COLOR_BLUE . '"></i>';

        if (isset($ssl['validTo_time_t']) && ($ssl['validTo_time_t'] - \time() > 0)) {
            $isValid = $check;
        } else {
            $isValid = $vulnerable;
        }

        if (false !== $ssl) {
            $certInfos = [
                $this->l('Is valid') => $isValid,
                $this->l('Common name') => $ssl['subject']['CN'],
                $this->l('Alternative names') => \str_replace('DNS:', '', $ssl['extensions']['subjectAltName']),
                $this->l('Issuer') => $ssl['issuer']['CN'],
                $this->l('Valid from') => \date('Y-m-d', ($ssl['validFrom_time_t'])),
                $this->l('Valid to') => \date('Y-m-d', ($ssl['validTo_time_t'])),
                $this->l('Expires in') => \round(($ssl['validTo_time_t'] - \time()) / (86400)) . ' ' . $this->l('days'),
            ];

            $tlsVersion = [];
            $tlsVersion['name'] = $this->l('Version') . ' (' . $data['tls_version'] . ')';
            if ('TLS 1.2' === $data['tls_version'] || 'TLS 1.3' === $data['tls_version']) {
                $tlsVersion['description'] = $this->l('Your client is using') . ' ' . $data['tls_version'] . ', ' . $this->l('the most modern version of the encryption protocol. It gives you access to the fastest, most secure encryption possible on the web.');
                $tlsVersion['check'] = $check;
            } elseif ('TLS 1.1' === $data['tls_version']) {
                $tlsVersion['description'] = $this->l('Your client is using
                TLS 1.1. It would be better to be TLS 1.2, but at least it isn\'t
                susceptible to the BEAST attack. But, it also doesn\'t have the
                AES-GCM cipher suite available.');
                $tlsVersion['check'] = $vulnerable;
            } else {
                $tlsVersion['description'] = $this->l('Your client is using') . ' ' . $data['tls_version'] . ', ' . $this->l('which is very old, possibly susceptible to the BEAST attack, and doesn\'t have the best cipher suites available on it. Additions like AES-GCM, and SHA256 to replace MD5-SHA-1 are unavailable to a TLS 1.0 client as well as many more modern cipher suites.');
                $tlsVersion['check'] = $vulnerable;
            }
            $tlsVersion['btn'] = $this->generateBtnLink($this->l('Learn more'), 'https://www.howsmyssl.com/s/about.html#version');

            $ephemeralKeysSupported = [];
            $ephemeralKeysSupported['name'] = $this->l('Ephemeral Key Support');
            if (true === $data['ephemeral_keys_supported']) {
                $ephemeralKeysSupported['description'] = $this->l('Ephemeral keys are used in some of the cipher suites your client supports. This means your client may be used to provide') . ' ' . $this->generateLink('https://en.wikipedia.org/wiki/Forward_secrecy', $this->l('forward secrecy')) . '. ' . $this->l('If the server supports it. This greatly increases your protection against snoopers, including global passive adversaries who scoop up large amounts of encrypted traffic and store them until their attacks (or their computers) improve.');
                $ephemeralKeysSupported['check'] = $check;
            } else {
                $ephemeralKeysSupported['description'] = $this->l('Ephemeral keys are not used in any of the cipher suites your client supports. This means your client cannot be used to provide') . ' ' . $this->generateLink('https://en.wikipedia.org/wiki/Forward_secrecy', $this->l('forward secrecy')) . '. ' . $this->l('Without it, global passive adversaries will be able to scoop up all of your encrypted traffic and decode it when their attacks or their computers are faster. This is actually happening.');
                $ephemeralKeysSupported['check'] = $vulnerable;
            }
            $ephemeralKeysSupported['btn'] = $this->generateBtnLink($this->l('Learn more'), 'https://www.howsmyssl.com/s/about.html#ephemeral-key-support');

            $sessionTicketSupported = [];
            $sessionTicketSupported['name'] = $this->l('Session Ticket Support');
            if (false === $data['session_ticket_supported']) {
                $sessionTicketSupported['description'] = $this->l('Session tickets are supported in your client. Services you use will be able to scale out their TLS connections more easily with this feature.');
                $sessionTicketSupported['check'] = $check;
            } else {
                $sessionTicketSupported['description'] = $this->l('Session tickets are not supported in your client. Without them, services will have a harder time making your client\'s connections fast. Generally, clients with ephemeral key support get this for free.');
                $sessionTicketSupported['check'] = $vulnerable;
            }
            $sessionTicketSupported['btn'] = $this->generateBtnLink($this->l('Learn more'), 'https://www.howsmyssl.com/s/about.html#session-ticket-support');

            $tlsCompressionSupported = [];
            $tlsCompressionSupported['name'] = $this->l('TLS Compression');
            if (true === $data['tls_compression_supported']) {
                $tlsCompressionSupported['description'] = $this->l('Your TLS client supports compressing the settings that encrypt your connection. This is really not good. It makes your TLS connections susceptible to the') . ' ' . $this->generateLink('https://en.wikipedia.org/wiki/CRIME', $this->l('CRIME attack')) . ' ' . $this->l('and your encrypted data could be leaked!');
                $tlsCompressionSupported['check'] = $vulnerable;
            } else {
                $tlsCompressionSupported['description'] = $this->l('Your TLS client does not attempt to compress the settings that encrypt your connection, avoiding information leaks from the') . ' ' . $this->generateLink('https://en.wikipedia.org/wiki/CRIME', $this->l('CRIME attack')) . '.';
                $tlsCompressionSupported['check'] = $check;
            }
            $tlsCompressionSupported['btn'] = $this->generateBtnLink($this->l('Learn more'), 'https://www.howsmyssl.com/s/about.html#tls-compression');

            $beastVuln = [];
            $beastVuln['name'] = $this->l('BEAST Vulnerability');
            if (true === $data['beast_vuln']) {
                if (true === $data['able_to_detect_n_minus_one_splitting']) {
                    $beastVuln['description'] = $this->l('Your client is open to the') . ' ' . $this->generateLink('https://en.wikipedia.org/wiki/Transport_Layer_Security#BEAST_attack', $this->l('BEAST attack')) . '. ' . $this->l('It\'s using TLS 1.0 or earlier while also supporting a cipher suite that uses') . ' ' . $this->generateLink('https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation', $this->l('Cipher-Block Chaining')) . ' ' . $this->l('and doesn\'t implement the 1/n-1 record splitting mitigation. That combination will leak information.');
                    $beastVuln['check'] = $vulnerable;
                } else {
                    $beastVuln['description'] = $this->l('Your client is probably open to the') . $this->generateBtnLink('https://en.wikipedia.org/wiki/Transport_Layer_Security#BEAST_attack', $this->l('BEAST attack')) . ' ' . $this->l('because it\'s using TLS 1.0 or earlier while also supporting a cipher suite that uses') . ' ' . $this->generateLink('https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation', $this->l('Cipher-Block Chaining')) . '. ' . $this->l('However, the CBC cipher suites your client supports is not one How\'s My SSL is able to use, so it was unable to determine if your client implements the 1/n-1 record splitting mitigation. Clients with that uncommon of cipher suite selection rarely implement it, however, so it\'s best to assume the worst.');
                }
                $beastVuln['check'] = $check;
            } else {
                if (true === $data['able_to_detect_n_minus_one_splitting']) {
                    $beastVuln['description'] = $this->l('Your client is not vulnerable to the') . ' ' . $this->generateLink('https://en.wikipedia.org/wiki/Transport_Layer_Security#BEAST_attack', $this->l('BEAST attack')) . ' ' . $this->l('While it\'s using TLS 1.0 in conjunction with') . ' ' . $this->generateLink('https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher-block_chaining_.28CBC.29', $this->l('Cipher-Block Chaining')) . ' ' . $this->l('cipher suites, it has implemented the 1/n-1 record splitting mitigation.');
                    $beastVuln['check'] = $check;
                } else {
                    $beastVuln['description'] = $this->l('Your client is not vulnerable to the') . ' ' . $this->generateLink('https://en.wikipedia.org/wiki/Transport_Layer_Security#BEAST_attack', $this->l('BEAST attack')) . ' ' . $this->l('because it\'s using a TLS protocol newer than TLS 1.0. The BEAST attack is only possible against clients using TLS 1.0 or earlier using') . ' ' . $this->generateLink('https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher-block_chaining_.28CBC.29', $this->l('Cipher-Block Chaining')) . ' ' . $this->l('cipher suites that don\'t implement the 1/n-1 record splitting mitigation.');
                    $beastVuln['check'] = $check;
                }
            }
            $beastVuln['btn'] = $this->generateBtnLink($this->l('Learn more'), 'https://www.howsmyssl.com/s/about.html#beast-vulnerability');

            $insecureCipherSuites = [];
            $insecureCipherSuites['name'] = $this->l('Insecure Cipher Suites');
            if (!empty($data['insecure_cipher_suites'])) {
                $insecureCipherSuites['description'] = $this->l('Your client supports cipher suites that are known to be insecure') . ': ' . \implode(', ', $data['insecure_cipher_suites']);
                $insecureCipherSuites['check'] = $vulnerable;
            } else {
                $insecureCipherSuites['description'] = $this->l('Your client doesn\'t use any cipher suites that are known to be insecure.');
                $insecureCipherSuites['check'] = $check;
            }
            $insecureCipherSuites['btn'] = $this->generateBtnLink($this->l('Learn more'), 'https://www.howsmyssl.com/s/about.html#insecure-cipher-suites');

            $givenCipherSuites = [];
            $givenCipherSuites['name'] = $this->l('Given cipher suites');
            if (!empty($data['given_cipher_suites'])) {
                $givenCipherSuites['description'] = $this->l('The cipher suites your client said it supports, in the order it sent them, are') . ': ' . \implode(', ', $data['given_cipher_suites']);
            } else {
                $givenCipherSuites['description'] = $this->l('Your client doesn\'t use any cipher suites that are known to be insecure.');
            }
            $givenCipherSuites['check'] = $possible;
            $givenCipherSuites['btn'] = $this->generateBtnLink($this->l('Learn more'), 'https://www.howsmyssl.com/s/about.html#given-cipher-suites');

            $mixedContent = [];
            $mixedContent['name'] = $this->l('Mixed content');
            $mixedContent['description'] = $this->l('Mixed content occurs when initial HTML is loaded over a secure HTTPS connection, but other resources (such as images, videos, stylesheets, scripts) are loaded over an insecure HTTP connection. This is called mixed content because both HTTP and HTTPS content are being loaded to display the same page, and the initial request was secure over HTTPS. Modern browsers display warnings about this type of content to indicate to the user that this page contains insecure resources.');
            $mixedContent['check'] = $possible;
            $mixedContent['btn'] = $this->disabledBtn($this->l('Scan for mixed content'));

            $sslAnalyze = [];
            $sslAnalyze['name'] = $this->l('Analyze SSL/TLS');
            $sslAnalyze['description'] = $this->l('Scan your website with SSL Labs. It can give you a better understanding of how your SSL/TLS is deployed.');
            $sslAnalyze['check'] = $possible;
            $sslAnalyze['btn'] = $this->disabledBtn($this->l('Analyze SSL/TLS'));

            $certChecks = [
                [
                    $tlsVersion['name'],
                    $tlsVersion['description'],
                    $tlsVersion['check'],
                    $tlsVersion['btn'],
                ],
                [
                    $ephemeralKeysSupported['name'],
                    $ephemeralKeysSupported['description'],
                    $ephemeralKeysSupported['check'],
                    $ephemeralKeysSupported['btn'],
                ],
                [
                    $sessionTicketSupported['name'],
                    $sessionTicketSupported['description'],
                    $sessionTicketSupported['check'],
                    $sessionTicketSupported['btn'],
                ],
                [
                    $tlsCompressionSupported['name'],
                    $tlsCompressionSupported['description'],
                    $tlsCompressionSupported['check'],
                    $tlsCompressionSupported['btn'],
                ],
                [
                    $beastVuln['name'],
                    $beastVuln['description'],
                    $beastVuln['check'],
                    $beastVuln['btn'],
                ],
                [
                    $insecureCipherSuites['name'],
                    $insecureCipherSuites['description'],
                    $insecureCipherSuites['check'],
                    $insecureCipherSuites['btn'],
                ],
                [
                    $givenCipherSuites['name'],
                    $givenCipherSuites['description'],
                    $givenCipherSuites['check'],
                    $givenCipherSuites['btn'],
                ],
                [
                    $mixedContent['name'],
                    $mixedContent['description'],
                    $mixedContent['check'],
                    $mixedContent['btn'],
                ],
                [
                    $sslAnalyze['name'],
                    $sslAnalyze['description'],
                    $sslAnalyze['check'],
                    $sslAnalyze['btn'],
                ],
            ];

            $certResult = [];
            foreach ($certInfos as $certInfo => $key) {
                $certResult[] = [
                    $this->l('Title') => $certInfo,
                    $this->l('Description') => $key,
                ];
            }

            $checkResult = [];
            foreach ($certChecks as $certCheck) {
                $checkResult[] = [
                    $this->l('Title') => $certCheck[0],
                    $this->l('Description') => $certCheck[1],
                    $this->l('Check') => $certCheck[2],
                    null => '<span class="securitylite-position" style="padding: 10px 0 10px 0;">' . $certCheck[3] . '</span>',
                ];
            }

            $total = $this->arrayToTable($certResult) . '<br>' . $this->addAlertWarning($this->l('The test below is performed between your client/browser and your website.')) . $this->arrayToTable($checkResult);
        } else {
            $total = $this->addAlertWarning($this->l('You must install a TLS certificate and') . ' ' . $this->generateLink($this->getAdminLink('AdminPreferences', true), $this->l('enable SSL everywhere')) . ' ' . $this->l('before the analysis can be performed.'));
        }

        return [
            'form' => [
                'legend' => [
                    'title' => $this->l('Analyze SSL/TLS'),
                    'icon' => 'icon-list',
                ],
                'description' => $this->l('The main use case for SSL/TLS is secure communications between a client and a server, but it is also used to secure your e-mails.'),
                'input' => [
                    [
                        'type' => 'html',
                        'label' => '',
                        'html_content' => $total,
                        'col' => 12,
                        'name' => '',
                    ],
                ],
            ],
        ];
    }

    /**
     * @return array
     */
    protected function fieldsFormAnalyzeModules()
    {
        $trusted = [];
        $result = null;

        // Not trusted modules
        if (null !== $this->getModules(false)) {
            foreach ($this->getModules(false) as $notTrustedModule) {
                $trusted[] = [
                    $this->l('Module') => $notTrustedModule,
                    $this->l('Trusted') => $this->proFeature,
                ];
            }
        }

        // Trusted modules
        if (null !== $this->getModules(true)) {
            foreach ($this->getModules(true) as $trustedModule) {
                $trusted[] = [
                    $this->l('Module') => $trustedModule,
                    $this->l('Trusted') => $this->proFeature,
                ];
            }
        }

        if (!empty($trusted)) {
            $result = $this->arrayToTable($trusted);
        }

        return [
            'form' => [
                'legend' => [
                    'title' => $this->l('Analyze Modules'),
                    'icon' => 'icon-list',
                ],
                'description' => $this->l('Modules that are nonnative PrestaShop modules or are not bought from PrestaShop Addons are untrusted. This means that they are not verified by PrestaShop. All of these modules can be safe even though they are not verified by PrestaShop, but be careful - in some cases these modules don\'t follow PrestaShop guidance and they can be insecure.') . ' ' . $this->l('Generally, third party modules provide additional security risks. Sometimes websites are hacked though insecure third-party modules. If there are any modules that you don\'t need, it is recommended to uninstall them.'),
                'input' => [
                    [
                        'type' => 'html',
                        'label' => '',
                        'html_content' => $result,
                        'col' => 12,
                        'name' => '',
                    ],
                ],
            ],
        ];
    }

    /**
     * @return array
     */
    protected function fieldsFormTools()
    {
        $buttons = [
            [
                $this->l('Port scanner'),
                $this->l('Check for open ports on your network. If you have unused open ports, consider closing them.') . '<br>' . $this->l('Generate a report to see which ports are open.'),
                '<span>' . $this->generateBtnPost('<i class="icon icon-file-text-o"></i> ' . $this->l('Generate report'), 'PortScannerAnalyze', false) . '</span>',
            ],
            [
                $this->l('RBL checker'),
                $this->l('Check if your server IP address is listed on the most common RBL\'s (Realtime Blackhole List).') . '<br>' . $this->l('Generate a report with the test results.'),
                '<span>' . $this->generateBtnPost('<i class="icon icon-file-text-o"></i> ' . $this->l('Generate report'), 'RblCheckerAnalyze', false) . '</span>',
            ],
            [
                $this->l('File permissions'),
                $this->l('Check the systems file- and folder permissions. This tool can fix insecure file- and folder permissions.') . ' ' . $this->l('File permission must be 644 and folder permissions must be 755.') . '<br>' . $this->l('Generate a report to see permissions that must be changed.') . ' ' . $this->l('Start by generating a report to see the consequence.'),
                '<span>' . $this->disabledBtn('<i class="icon icon-check"></i> ' . $this->l('Fix vulnerability')) . '</span><span class="securitylite-divider"></span><span>' . $this->generateBtnPost('<i class="icon icon-file-text-o"></i> ' . $this->l('Generate report'), 'PermissionsAnalyze', false) . '</span>',
            ],
            [
                $this->l('Directory traversal'),
                $this->l('Check the system for directory traversal security vulnerability.') . ' ' . $this->l('This tool can add missing index.php files to the theme- and module directories.') . '<br>' . $this->l('Generate a report to see which paths are missing the index.php file.'),
                '<span>' . $this->disabledBtn('<i class="icon icon-check"></i> ' . $this->l('Fix vulnerability')) . '</span><span class="securitylite-divider"></span><span>' . $this->generateBtnPost('<i class="icon icon-file-text-o"></i> ' . $this->l('Generate report'), 'CreateIndexAnalyze', false) . '</span>',
            ],
            [
                $this->l('Delete files'),
                $this->l('Check the system for files that should be removed due to security reasons.') . ' ' . $this->l('This tool can remove these files. These files could be files leftover from the installation.') . '<br>' . $this->l('Generate a report to see which files should be deleted.') . ' ' . $this->l('Deleting files is permanent. Start by generating a report to see the consequence.'),
                '<span>' . $this->disabledBtn('<i class="icon icon-check"></i> ' . $this->l('Fix vulnerability')) . '</span><span class="securitylite-divider"></span><span>' . $this->generateBtnPost('<i class="icon icon-file-text-o"></i> ' . $this->l('Generate report'), 'RemoveFilesAnalyze', false) . '</span>',
            ],
        ];

        $table = [];
        $text = [];

        foreach ($buttons as $button) {
            $table[] = [
                $this->l('Title') => $button[0],
                $this->l('Description') => $button[1],
                null => '<span class="securitylite-position" style="padding: 8px 0 8px 0;">' . $button[2] . '</span>',
            ];
        }

        $text[] = $this->arrayToTable($table);

        return [
            'form' => [
                'legend' => [
                    'title' => $this->l('Tools'),
                    'icon' => 'icon-wrench',
                ],
                'description' => $this->l('These tools can fix some known vulnerabilities. Some of these tools need up to 2 min. to run. Please wait until the page has finished loading.'),
                'input' => [
                    [
                        'type' => 'html',
                        'label' => '',
                        'html_content' => \implode('', $text),
                        'col' => 12,
                        'name' => '',
                    ],
                ],
            ],
        ];
    }

    /**
     * @return array
     */
    protected function fieldsFormBackup()
    {
        $backupDir = _PS_MODULE_DIR_ . 'securitylite/backup';
        if (!\is_dir($backupDir . '/database/')) {
            \mkdir($backupDir . '/database/', 0755, true);
            $this->addIndexRecursively($backupDir);
            \file_put_contents($backupDir . '/.htaccess', $this->getHtaccessContent());
        }

        $dirPath = [];
        $ext = [
            'bz2',
            'gz',
        ];

        if ($handle = \opendir(_PS_MODULE_DIR_ . $this->name . self::DIR_BACKUP_DATABASE)) {
            while (false !== ($entry = \readdir($handle))) {
                if ('.' !== $entry && '..' !== $entry) {
                    if (\in_array(\pathinfo(\basename($entry), \PATHINFO_EXTENSION), $ext, true)) {
                        $pathToFile = \realpath(_PS_MODULE_DIR_ . $this->name . self::DIR_BACKUP_DATABASE . $entry);
                        $date = \date('Y-m-d', \Tools::substr(\basename($entry), 0, 10));
                        $dirPath[] = '<a onclick="return confirm(\'' . $this->l('Are you sure, you want to delete') . ' ' . $entry . '?\')" href="' . $this->currentAdminIndex() . '&BackupDatabaseDelete=1&file=' . $entry . '"><i style="color: ' . self::COLOR_RED . ';" class="icon icon-trash-o"></i></a> <a href="' . $this->currentAdminIndex() . '&BackupDatabaseDownload=1&file=' . $entry . '"><i style="color: ' . self::COLOR_GREEN . ';" class="icon icon-download"></i></a> ' . Tools::formatBytes(\filesize($pathToFile), 1) . 'B | ' . $pathToFile . ' (' . $date . ')';
                    }
                }
            }
        }

        return [
            'form' => [
                'legend' => [
                    'title' => $this->l('Automatic Backups'),
                    'icon' => 'icon-files-o',
                ],
                'description' => $this->l('Keeping a backup may be your easiest and best protection; allowing you to turn back the clock after an attack. While this doesn\'t prevent attacks, it does cure them when needed.') . ' ' . $this->generateLink('https://en.wikipedia.org/wiki/Backup', $this->l('Read more')) . '.',
                'warning' => $this->l('Security Lite') . ' ' . $this->l('is not responsible for your database/files, its backups, and/or recovery.') . '<br>' .
                $this->l('You should back up your data regularly (both files and databases).') . '<br>' .
                $this->l('Security Lite') . ' ' . $this->l('can back up your database and saves it locally.') . '<br>' .
                $this->l('Always verify the quality and integrity of your backup files!') . '<br>' .
                $this->l('Always verify that your backup files are complete, up-to-date, and valid, even if you had a success message appear during the backup process.') . '<br>' .
                $this->l('Always check your data.') . '<br>' .
                $this->l('Never restore a backup on a live site.'),
                'input' => [
                    [
                        'type' => 'switch',
                        'col' => 8,
                        'label' => $this->l('Backup database to Dropbox'),
                        'name' => 'LITE_BACKUP_DB_DROPBOX',
                        'is_bool' => true,
                        'desc' => $this->proFeature . $this->l('Save a backup of your database to your Dropbox. Statistical data are excluded.') . ' ' . $this->l('Once this option is enabled, a cronjob will appear in your dashboard that you need to set up.'),
                        'disabled' => true,
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
                        'col' => 8,
                        'label' => $this->l('Backup database to local'),
                        'name' => 'LITE_BACKUP_DB',
                        'is_bool' => true,
                        'desc' => $this->l('Save a local backup of your database. Statistical data are excluded.') . ' ' . $this->l('Once this option is enabled, a cronjob will appear in your dashboard that you need to set up.'),
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
                        'col' => 4,
                        'type' => 'text',
                        'prefix' => '<i class="icon-floppy-o"></i>',
                        'desc' => $this->l('Old backups will be deleted when a newer one is generated. How many backups do you want to keep at the time? Write, \'0\' for unlimited backups.'),
                        'name' => 'LITE_BACKUP_DB_SAVED',
                        'label' => $this->l('Database backups to save'),
                        'suffix' => $this->l('backups'),
                        'hint' => $this->l('Must be an integer'),
                        'required' => true,
                    ],
                    [
                        'type' => 'switch',
                        'col' => 8,
                        'label' => $this->l('Backup files to Dropbox'),
                        'name' => 'LITE_BACKUP_FILE_DROPBOX',
                        'is_bool' => true,
                        'disabled' => true,
                        'desc' => $this->proFeature . $this->l('Save a full backup of your files to your Dropbox. Cache and log files are excluded.') . ' ' . $this->l('Once this option is enabled, a cronjob will appear in your dashboard that you need to set up.'),
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
                        'col' => 8,
                        'label' => $this->l('Backup files to local'),
                        'name' => 'LITE_BACKUP_FILE',
                        'is_bool' => true,
                        'disabled' => true,
                        'desc' => $this->proFeature . $this->l('Save a full backup of your files on your PrestaShop installation.') . ' ' . $this->l('Once this option is enabled, a cronjob will appear in your dashboard that you need to set up.'),
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
                        'col' => 4,
                        'type' => 'text',
                        'prefix' => '<i class="icon-floppy-o"></i>',
                        'disabled' => true,
                        'desc' => $this->proFeature . $this->l('Old backups will be deleted if a newer one is generated. How many backups do you want to keep at the time? Write, "0" for unlimited backups.'),
                        'name' => 'LITE_BACKUP_FILE_SAVED',
                        'label' => $this->l('File backups to save'),
                        'suffix' => $this->l('backups'),
                        'hint' => $this->l('Must be an integer'),
                        'required' => true,
                    ],
                    [
                        'type' => 'select',
                        'label' => $this->l('Zip compression level for file backup'),
                        'desc' => $this->proFeature . $this->l('The values range from 1 (super-fast) to 9 (maximum) are supported. The higher the number, the better and longer the compression.'),
                        'name' => 'LITE_BACKUP_COMPRESSION',
                        'disabled' => true,
                        'options' => [
                            'query' => [
                                [
                                    'id_option' => 'SUPER_FAST',
                                    'name' => '1 (' . $this->l('super-fast') . ')',
                                ],
                                [
                                    'id_option' => 'NORMAL',
                                    'name' => '5 (' . $this->l('normal') . ')',
                                ],
                                [
                                    'id_option' => 'MAXIMUM',
                                    'name' => '9 (' . $this->l('maximum') . ')',
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
     * @return array
     */
    protected function fieldsFormPasswdGen()
    {
        return [
            'form' => [
                'legend' => [
                    'title' => $this->l('Password Generator'),
                    'icon' => 'icon-refresh',
                ],
                'description' => $this->l('You should use a strong and unique password for each of MySQL database, FTP, hosting panel/cPanel, SSH access, and back office. You can use this tool to generate passwords.') . ' ' . $this->generateLink('https://en.wikipedia.org/wiki/Password_strength', $this->l('Read more')) . '.',
                'input' => [
                    [
                        'col' => 6,
                        'type' => 'textbutton',
                        'label' => $this->l('Generate a strong password'),
                        'desc' => $this->l('The password is not saved anywhere by this module.'),
                        'name' => 'LITE_PASSWORD_GENERATOR',
                        'button' => [
                            'label' => $this->l('Generate'),
                            'attributes' => [
                                'onclick' => 'addField1();',
                            ],
                        ],
                    ],
                ],
            ],
        ];
    }

    /**
     * @return array
     */
    protected function fieldsFormBruteForceProtection()
    {
        return [
            'form' => [
                'legend' => [
                    'title' => $this->l('Admin Brute Force Protection'),
                    'icon' => 'icon-lock',
                ],
                'description' => $this->l('A brute force attack is one of the simplest methods to gain access to a website. The hacker tries various combinations of usernames and passwords again and again until he gets in. The module can limit the tries to protect you from the attack.') . ' ' . $this->generateLink('https://en.wikipedia.org/wiki/Brute-force_attack', $this->l('Read more')) . '.',
                'input' => [
                    [
                        'col' => 8,
                        'type' => 'switch',
                        'col' => 8,
                        'label' => $this->l('Brute force protection'),
                        'name' => 'LITE_FAIL2BAN',
                        'is_bool' => true,
                        'desc' => $this->l('Enable brute force protection to limits the greatest amount of login tries to your back office.'),
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
                        'col' => 4,
                        'type' => 'text',
                        'desc' => $this->l('Wrong answers before the ban.') . ' ' . $this->l('The default value is') . ' 5.',
                        'name' => 'LITE_MAX_RETRY',
                        'prefix' => '<i class="icon-repeat"></i>',
                        'suffix' => $this->l('times'),
                        'label' => $this->l('Max retries'),
                        'hint' => $this->l('Must be an integer'),
                        'required' => true,
                    ],
                    [
                        'col' => 4,
                        'type' => 'text',
                        'desc' => $this->l('A host is banned if it has generated') . ' \'' . $this->l('Max retry') . '\' ' . $this->l('during the last') . ' \'' . $this->l('Request timeout') . '\'. ' . $this->l('Enter time in minutes') . '. ' . $this->l('The default value is') . ' 10.',
                        'name' => 'LITE_FIND_TIME',
                        'prefix' => '<i class="icon-clock-o"></i>',
                        'suffix' => $this->l('minutes'),
                        'label' => $this->l('Request timeout'),
                        'hint' => $this->l('Must be an integer'),
                        'required' => true,
                    ],
                    [
                        'col' => 4,
                        'type' => 'text',
                        'desc' => $this->l('Time a host is banned. Enter time in minutes.') . ' ' . $this->l('The default value is') . ' 30.',
                        'name' => 'LITE_BAN_TIME',
                        'prefix' => '<i class="icon-clock-o"></i>',
                        'suffix' => $this->l('minutes'),
                        'label' => $this->l('Ban time'),
                        'hint' => $this->l('Must be an integer'),
                        'required' => true,
                    ],
                    [
                        'type' => 'switch',
                        'col' => 8,
                        'label' => $this->l('Receive e-mail on failing to login'),
                        'name' => 'LITE_SEND_MAIL',
                        'is_bool' => true,
                        'desc' => $this->proFeature . $this->l('Receive an e-mail if someone inputs a wrong password. This setting can only be enabled if brute force protection is activated.'),
                        'disabled' => true,
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
                        'col' => 8,
                        'label' => $this->l('Receive e-mail on successful login'),
                        'name' => 'LITE_SEND_MAIL_LOGIN',
                        'is_bool' => true,
                        'desc' => $this->proFeature . $this->l('Receive an e-mail in case someone inputs the correct password. This feature is great to give you the information if anyone else got access. This setting can only be enabled if brute force protection is activated.'),
                        'disabled' => true,
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
                        'type' => 'textbutton',
                        'col' => 8,
                        'desc' => $this->proFeature . $this->l('You can list your IP addresses to avoid getting an e-mail if you write the password wrong. You can still get banned for some time if you fail to login according to your own rules above.') . '<br>' . $this->l('The module can handle IPv4 and IPv6 addresses, as well as IP ranges, in CIDR formats like') . ' <code>::1/128</code> ' . $this->l('or') . ' <code>127.0.0.1/32</code> ' . $this->l('and pattern format like') . ' <code>::*:*</code> ' . $this->l('or') . ' <code>127.0.*.*</code>. ' . $this->l('Separates by a comma') . ' (\',\') ' . $this->l('without space.'),

                        'name' => 'LITE_WHITELIST_IPS',
                        'button' => [
                            'label' => '<i class="icon-plus"></i> ' . $this->l('Add my IP'),
                            'attributes' => [
                                'onclick' => '',
                            ],
                        ],
                        'disabled' => true,
                        'label' => $this->l('Whitelist IP addresses'),
                        'hint' => $this->l('E.g.') . ' 123.456.789,123.456.*,123.*,...',
                    ],
                    [
                        'type' => 'switch',
                        'col' => 8,
                        'label' => $this->l('Log banned users'),
                        'name' => 'LITE_FAIL2BAN_LOG',
                        'is_bool' => true,
                        'desc' => $this->proFeature . $this->l('Record banned users into a log file.') . ' ' . $this->l('The log can be found on your dashboard.'),
                        'disabled' => true,
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

    /**
     * @return array
     */
    protected function fieldsFormHttpSecurityHeaders()
    {
        return [
            'form' => [
                'legend' => [
                    'title' => $this->l('HTTP Security Headers'),
                    'icon' => 'icon-shield',
                ],
                'description' => $this->l('Security headers are HTTP response headers that your application can use to increase the security of your application. Once set, these HTTP response headers can restrict browsers from running into easily preventable vulnerabilities.') . ' ' . $this->l('This module makes the configuration of these security headers easy.'),
                'input' => [
                    [
                        'type' => 'switch',
                        'col' => 8,
                        'label' => $this->l('Click-jack protection'),
                        'name' => 'LITE_CLICK_JACKING',
                        'is_bool' => true,
                        'desc' => $this->proFeature . $this->l('Prevent browsers from framing your site. This will defend you against attacks like click-jacking.'),
                        'disabled' => true,
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
                        'col' => 8,
                        'label' => $this->l('XSS protection'),
                        'name' => 'LITE_X_XSS_PPROTECTION',
                        'is_bool' => true,
                        'desc' => $this->proFeature . $this->l('Set secure configuration for the cross-site scripting filters built into most browsers.'),
                        'disabled' => true,
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
                        'col' => 8,
                        'label' => $this->l('Disable content sniffing'),
                        'name' => 'LITE_X_CONTENT_TYPE_OPTIONS',
                        'is_bool' => false,
                        'desc' => $this->proFeature . $this->l('Stop browsers from trying to MIME-sniff the content type and forces it to stick with the declared content-type.'),
                        'disabled' => true,
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
                        'col' => 8,
                        'label' => $this->l('Force secure connection with HSTS'),
                        'name' => 'LITE_STRICT_TRANSPORT_SECURITY',
                        'is_bool' => true,
                        'desc' => $this->proFeature . $this->l('Strengthens your implementation of TLS by getting the user agent to enforce the use of HTTPS.'),
                        'disabled' => true,
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
                        'type' => 'checkbox',
                        'desc' => $this->proFeature . $this->l('Please follow this link to understand these settings') . ': ' . $this->generateLink('https://hstspreload.org/?domain=' . $this->getShopUrl()) . '.',
                        'label' => $this->l('HSTS settings'),
                        'name' => 'LITE_HSTS_SETTINGS',
                        'disabled' => true,
                        'values' => [
                            'query' => [
                                [
                                    'id_option' => 0,
                                    'name' => 'Preload',
                                    'value' => 0,
                                ],
                                [
                                    'id_option' => 1,
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
                        'type' => 'switch',
                        'col' => 8,
                        'label' => $this->l('Expect CT'),
                        'name' => 'LITE_EXPECT_CT',
                        'is_bool' => true,
                        'desc' => $this->proFeature . $this->l('Signals to the user agent that compliance with the certificate transparency policy should be enforced.'),
                        'disabled' => true,
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
                        'col' => 8,
                        'label' => $this->l('Referrer policy'),
                        'name' => 'LITE_REFFERER_POLICY',
                        'is_bool' => true,
                        'desc' => $this->proFeature . $this->l('The browser will send a full URL along with requests from a TLS-protected environment settings object to a potentially trustworthy URL and requests from clients which are not TLS-protected to any origin.'),
                        'disabled' => true,
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
                        'col' => 8,
                        'label' => $this->l('Access control allows methods'),
                        'name' => 'LITE_ACCESS_CONTROL_ALLOW_METHODS',
                        'is_bool' => true,
                        'desc' => $this->proFeature . $this->l('The server responds and says that only POST, GET, OPTIONS are viable methods to query the resource in question.'),
                        'disabled' => true,
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
                        'col' => 8,
                        'label' => $this->l('Permitted cross-domain policies'),
                        'name' => 'LITE_X_PERITTED_CROSS_DOMAIN_POLICY',
                        'is_bool' => true,
                        'desc' => $this->proFeature . $this->l('Prevent Adobe Flash and Adobe Acrobat from loading content on your site. This protects against cross-domain middleware.'),
                        'disabled' => true,
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
                        'col' => 8,
                        'label' => $this->l('Download options'),
                        'name' => 'LITE_X_DOWNLOAD_OPTIONS',
                        'is_bool' => true,
                        'desc' => $this->proFeature . $this->l('This disables the option to open a file directly on download.') . ' ' . $this->l('This header is only supported by Internet Explorer.'),
                        'disabled' => true,
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
                        'col' => 8,
                        'label' => $this->l('Hide server information'),
                        'name' => 'LITE_UNSET_HEADERS',
                        'is_bool' => true,
                        'disabled' => true,
                        'desc' => $this->proFeature . $this->l('Remove all') . ' \'Powered-by\' ' . $this->l('HTTP headers and hide server information.') . '<br><br><br><a class="btn btn-default" style="font-style: normal; margin-bottom: 4px;" href="https://securityheaders.com/?q=' . $this->getShopUrl() . '&amp;hide=on&amp;followRedirects=on" target="_blank" rel="noopener noreferrer">' . $this->l('Analyze security HTTP headers') . '</a><br>' . $this->l('Security Lite') . ' ' . $this->l('can fix all warnings and errors reported by') . ' ' . $this->generateLink('https://securityheaders.com') . ' ' . $this->l('you can get an') . ' <strong style="color: ' . self::COLOR_GREEN . ';">A+</strong> ' . $this->l('score') . '!',
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

    /**
     * @return array
     */
    protected function fieldsFormSecondLogin()
    {
        return [
            'form' => [
                'legend' => [
                    'title' => $this->l('Second Login'),
                    'icon' => 'icon-sign-in',
                ],
                'description' => $this->l('Your shop is already secured by PrestaShop\'s login, but you can add another layer of security by adding a second login from your webserver itself. This is done using .htpasswd (Apache-servers only).') . ' ' . $this->l('The second login is the same for each employee, as this is set on the server level.'),
                'warning' => $this->l('This feature is for advanced users only. It is recommended to leave this feature off in most cases.'),
                'input' => [
                    [
                        'type' => 'switch',
                        'col' => 8,
                        'label' => $this->l('Second login'),
                        'name' => 'LITE_HTPASSWD',
                        'is_bool' => true,
                        'desc' => $this->proFeature . $this->l('Activate a second login from your webserver itself.'),
                        'disabled' => true,
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
                        'col' => 4,
                        'type' => 'text',
                        'prefix' => '<i class="icon-user"></i>',
                        'desc' => $this->proFeature . $this->l('You should use another username then you do for your regular back office login.') . ' <a onclick="" href="javascript:void(0)">' . $this->l('Generate a secure username') . '</a>.',
                        'name' => 'LITE_HTPASSWD_USER',
                        'label' => $this->l('Username'),
                        'hint' => $this->l('Invalid character') . ': \':\'',
                        'disabled' => true,
                    ],
                    [
                        'col' => 4,
                        'type' => 'text',
                        'prefix' => '<i class="icon-key"></i>',
                        'desc' => $this->proFeature . $this->l('You should use another password than you do for your regular back office login.') . ' <a onclick="" href="javascript:void(0)">' . $this->l('Generate a secure password') . '</a>.',
                        'name' => 'LITE_HTPASSWD_PASS',
                        'label' => $this->l('Password'),
                        'hint' => $this->l('Invalid character') . ': \':\'',
                        'disabled' => true,
                    ],
                ],
                'submit' => [
                    'title' => $this->l('Save'),
                ],
            ],
        ];
    }

    /**
     * @return array
     */
    protected function fieldsFormAdminStealthLogin()
    {
        return [
            'form' => [
                'legend' => [
                    'title' => $this->l('Admin Stealth Login'),
                    'icon' => 'icon-eye-slash',
                ],
                'description' => $this->l('Admin Stealth Login makes your admin directory invisible for hosts with unknown IP addresses.'),
                'warning' => $this->l('This feature is for advanced users only. It is recommended to leave this feature off in most cases.'),
                'disabled' => true,
                'input' => [
                    [
                        'type' => 'switch',
                        'col' => 8,
                        'label' => $this->l('Admin stealth login'),
                        'name' => 'LITE_STEALTH_LOGIN',
                        'is_bool' => true,
                        'desc' => $this->proFeature . $this->l('Block access to the back office for everyone except the IP addresses on the list below.') . ' <strong>' . $this->l('You must have a static IP address') . '.</strong> ' . $this->generateLink('https://en.wikipedia.org/wiki/IP_address#Static_IP', $this->l('Read more')) . '.',
                        'disabled' => true,
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
                        'col' => 8,
                        'type' => 'textbutton',
                        'label' => $this->l('Whitelist'),
                        'hint' => $this->l('E.g.') . ' 123.456.789,123.456.*,123.*,...',
                        'desc' => $this->proFeature . $this->l('List all the IP addresses that should have access to back office.') . '<br>' . $this->l('The module can handle IPv4 and IPv6 addresses, as well as IP ranges, in CIDR formats like') . ' <code>::1/128</code> ' . $this->l('or') . ' <code>127.0.0.1/32</code> ' . $this->l('and pattern format like') . ' <code>::*:*</code> ' . $this->l('or') . ' <code>127.0.*.*</code>. ' . $this->l('Separates by a comma') . ' (\',\') ' . $this->l('without space.'),
                        'name' => 'LITE_STEALTH_LOGIN_WHITELIST',
                        'disabled' => true,
                        'button' => [
                            'label' => '<i class="icon-plus"></i> ' . $this->l('Add my IP'),
                            'attributes' => [
                                'onclick' => '',
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

    /**
     * @return array
     */
    protected function fieldsFormAntiSpam()
    {
        $linkRegistrationForm = $this->context->link->getPageLink('authentication') . '?create_account=1';

        return [
            'form' => [
                'legend' => [
                    'title' => $this->l('Anti-SPAM'),
                    'icon' => 'icon-ban',
                ],
                'description' => $this->l('SPAM (Shit Posing As Mail) is a problem for most businesses. There are still people who fall victim to cyber-attacks such as') . ' ' . $this->generateLink('https://en.wikipedia.org/wiki/Spamming', $this->l('spamming')) . ' ' . $this->l('and') . ' ' . $this->generateLink('https://en.wikipedia.org/wiki/Phishing', $this->l('phishing')) . '.',
                'input' => [
                    [
                        'type' => 'html',
                        'label' => '',
                        'html_content' => $this->addHeading($this->l('Contact form'), true),
                        'col' => 12,
                        'name' => '',
                    ],
                    [
                        'type' => 'switch',
                        'col' => 8,
                        'label' => $this->l('Disable contact form'),
                        'name' => 'LITE_DISABLE_CONTACT_FORM',
                        'is_bool' => true,
                        'desc' => $this->l('If you want to disable the contact form, you can enable this feature.'),
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
                        'col' => 8,
                        'label' => $this->l('Enable') . ' reCAPTCHA v3',
                        'name' => 'LITE_RECAPTCHA_V3_CONTACT_ACTIVATE',
                        'is_bool' => true,
                        'disabled' => true,
                        'desc' => $this->proFeature . $this->l('reCAPTCHA v3 returns a risk score for each request without user friction. This risk-score is used by the module to decide whether the user is a bot or a human. Bots will be prevented from sending e-mails.') . ' ' . $this->generateLink('https://www.google.com/recaptcha/about/', $this->l('Read more')) . '.',
                        'disabled' => true,
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
                        'col' => 8,
                        'label' => $this->l('Block vulnerable messages'),
                        'name' => 'LITE_GOOGLE_SAFE_BROWSING_V4_ACTIVATE',
                        'is_bool' => true,
                        'desc' => $this->proFeature . $this->l('Prevent users from sending e-mails with links to known phishing and deceptive sites using Google safe browsing API. The safe browsing API automatically checks the URLs in the message against Google\'s constantly updated lists of unsafe web resources. If any URL in the message is found on the safe browsing list, the message will be not be sent.') . ' ' . $this->generateLink('https://developers.google.com/safe-browsing', $this->l('Read more')) . '.',
                        'disabled' => true,
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
                        'col' => 8,
                        'label' => $this->l('Block custom words'),
                        'name' => 'LITE_MESSAGE_CHECKER_ACTIVATE',
                        'is_bool' => true,
                        'desc' => $this->proFeature . $this->l('Block message if it contains at least one word from your custom list of blacklisted words.'),
                        'disabled' => true,
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
                        'type' => 'textarea',
                        'col' => 8,
                        'desc' => $this->proFeature . $this->l('Custom list of bad words') . ' ' . $this->l('Separates by a comma') . ' (\',\') ' . $this->l('without space.'),
                        'name' => 'LITE_MESSAGE_CHECKER_CUSTOM_LIST',
                        'label' => $this->l('Blacklisted words'),
                        'hint' => $this->l('E.g.') . ' viagra,cialis,poker,casino',
                        'disabled' => true,
                    ],
                    [
                        'type' => 'switch',
                        'col' => 8,
                        'label' => $this->l('Block disposable e-mails'),
                        'name' => 'LITE_DISPOSABLE_EMAIL_PROVIDERS_ACTIVATE',
                        'is_bool' => true,
                        'desc' => $this->proFeature . $this->l('Block e-mails from disposable providers.'),
                        'disabled' => true,
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
                        'col' => 8,
                        'label' => $this->l('Block custom list of TLD\'s'),
                        'name' => 'LITE_EMAIL_CHECKER_ACTIVATE',
                        'is_bool' => true,
                        'desc' => $this->proFeature . $this->l('Block e-mails with specific top-level domains.'),
                        'disabled' => true,
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
                        'type' => 'textarea',
                        'col' => 8,
                        'name' => 'LITE_EMAIL_CHECKER_CUSTOM_LIST',
                        'label' => $this->l('Custom list of TLD\'s'),
                        'desc' => $this->proFeature . $this->l('Custom blacklist of top-level domains.') . ' ' . $this->l('Separates by a comma') . ' (\',\') ' . $this->l('without space.'),
                        'hint' => $this->l('E.g.') . ' ru,qq.com,vn',
                        'disabled' => true,
                    ],
                    [
                        'type' => 'html',
                        'label' => '',
                        'html_content' => $this->addHeading($this->l('Registration form')) . $this->addAlertInfo($this->l('This module does not use overrides. Therefore, it is not possible to add these checks on the registration at the checkout process. These checks are limited to this registration form') . ': ' . $this->generateLink($linkRegistrationForm)),
                        'col' => 12,
                        'name' => '',
                    ],
                    [
                        'type' => 'switch',
                        'col' => 8,
                        'label' => $this->l('Prevent fake accounts'),
                        'name' => 'LITE_FAKE_ACCOUNTS',
                        'is_bool' => true,
                        'disabled' => true,
                        'desc' => $this->proFeature . $this->l('Prevent bots from making fake accounts by setting a token.'),
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
                        'col' => 8,
                        'label' => $this->l('Disallow URL in customer name'),
                        'name' => 'LITE_DISALLOW_URL_CUSTOMER_NAME',
                        'is_bool' => true,
                        'disabled' => true,
                        'desc' => $this->proFeature . $this->l('Prevent bots from making fake accounts by verifying that first name and last name is not a URL.'),
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
                        'col' => 8,
                        'label' => $this->l('Enable') . ' reCAPTCHA v3',
                        'name' => 'LITE_RECAPTCHA_V3_REGISTRATION_ACTIVATE',
                        'is_bool' => true,
                        'disabled' => true,
                        'desc' => $this->proFeature . $this->l('reCAPTCHA v3 returns a risk score for each request without user friction. This risk-score is used by the module to determine whether the user is a bot or a human. Bots will be prevented from register accounts.') . ' ' . $this->generateLink('https://www.google.com/recaptcha/about/', $this->l('Read more')) . '.',
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
                        'col' => 8,
                        'label' => $this->l('Block disposable e-mails'),
                        'name' => 'LITE_DISPOSABLE_EMAIL_PROVIDERS_REGISTRATION_ACTIVATE',
                        'is_bool' => true,
                        'disabled' => true,
                        'desc' => $this->proFeature . $this->l('Block e-mails from disposable providers.'),
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
                        'col' => 8,
                        'label' => $this->l('Block custom list of TLD\'s'),
                        'name' => 'LITE_EMAIL_CHECKER_REGISTRATION_ACTIVATE',
                        'is_bool' => true,
                        'disabled' => true,
                        'desc' => $this->proFeature . $this->l('Block e-mails with a custom list of top-level domains.'),
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
                        'type' => 'textarea',
                        'col' => 8,
                        'name' => 'LITE_EMAIL_CHECKER_CUSTOM_LIST_REGISTRATION',
                        'label' => $this->l('Custom list of TLD\'s'),
                        'desc' => $this->proFeature . $this->l('Custom blacklist of top-level domains.') . ' ' . $this->l('Separates by a comma') . ' (\',\') ' . $this->l('without space.'),
                        'hint' => $this->l('E.g.') . ' ru,qq.com,vn',
                    ],
                ],
                'submit' => [
                    'title' => $this->l('Save'),
                ],
            ],
        ];
    }

    /**
     * @return array
     */
    protected function fieldsFormMalwareScan()
    {
        return [
            'form' => [
                'legend' => [
                    'title' => $this->l('Anti Malware'),
                    'icon' => 'icon-user-secret',
                ],
                'description' => $this->l('The term malware refers to software that damages devices, steal data, and causes chaos. There are many types of malware — viruses, trojans, spyware, ransomware, and more.') . ' ' . $this->generateLink('https://en.wikipedia.org/wiki/Malware', $this->l('Read more')) . '.',
                'input' => [
                    [
                        'type' => 'switch',
                        'col' => 8,
                        'label' => $this->l('Get an e-mail if malware is detected'),
                        'name' => 'LITE_MALWARE_SCAN_EMAIL',
                        'is_bool' => true,
                        'disabled' => true,
                        'desc' => $this->proFeature . $this->l('Scan all your directories for malware and let you know by e-mail if something was found.') . ' ' . $this->l('Once this option is enabled, a cronjob will appear in your dashboard that you need to set up.'),
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
                        'col' => 8,
                        'label' => $this->l('Log malware'),
                        'name' => 'LITE_MALWARE_SCAN_LOG',
                        'is_bool' => true,
                        'disabled' => true,
                        'desc' => $this->proFeature . $this->l('Scan all your directories for malware and log it if something was found.') . ' ' . $this->l('The log can be found on your dashboard.'),
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
                        'type' => 'textarea',
                        'col' => 8,
                        'desc' => $this->proFeature . $this->l('Whitelist false positives, caused by custom modules, etc.') . ' ' . $this->l('Separate files by a comma') . ' (\',\') ' . $this->l('without space.'),
                        'name' => 'LITE_WHITELIST_MALWARE',
                        'label' => $this->l('Whitelist filter for malware'),
                        'hint' => $this->l('E.g.') . ' file.js,file.php',
                    ],
                    [
                        'type' => 'switch',
                        'col' => 8,
                        'label' => $this->l('Log error 404'),
                        'name' => 'LITE_PAGE_NOT_FOUND_LOG',
                        'is_bool' => true,
                        'desc' => $this->l('Track every \'page not found\' (error 404) and log them into a log file. This is very useful to detect hacking attempts.'),
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

    /**
     * @return array
     */
    protected function fieldsFormAntiFakeCarts()
    {
        return [
            'form' => [
                'legend' => [
                    'title' => $this->l('Anti-Fake Carts'),
                    'icon' => 'icon-shopping-cart',
                ],
                'description' => $this->l('The module can automatically delete abandoned carts. Abandoned carts can be generated both by users and by crawlers, resulting in a massive amount of useless data that severely affects the performances of your shop database.'),
                'input' => [
                    [
                        'type' => 'switch',
                        'col' => 8,
                        'label' => $this->l('Delete old carts'),
                        'name' => 'LITE_DELETE_OLD_CARTS',
                        'is_bool' => true,
                        'desc' => $this->l('Delete unused carts after a certain number of days.') . ' ' . $this->l('Once this option is enabled, a cronjob will appear in your dashboard that you need to set up.'),
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
                        'col' => 4,
                        'type' => 'text',
                        'suffix' => $this->l('days'),
                        'desc' => $this->l('Allowed days a cart must be saved before it is automatically deleted.') . ' ' . $this->l('14 days is recommended.'),
                        'name' => 'LITE_DELETE_OLD_CARTS_DAYS',
                        'label' => $this->l('Max days'),
                        'hint' => $this->l('Must be an integer'),
                        'required' => true,
                    ],
                    [
                        'type' => 'switch',
                        'col' => 8,
                        'label' => $this->l('Prevent crawlers from adding to the cart'),
                        'name' => 'LITE_BLOCK_ADD_TO_CART',
                        'is_bool' => true,
                        'disabled' => true,
                        'desc' => $this->proFeature . $this->l('Crawlers that don\'t respect your robot.txt rules might click the add to cart button. This can lead to a lot of unused carts that will slow down your site. This feature will block crawlers from adding to cart.'),
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

    /**
     * @return array
     */
    protected function fieldsFormFirewall()
    {
        return [
            'form' => [
                'legend' => [
                    'title' => $this->l('Web Application Firewall'),
                    'icon' => 'icon-repeat',
                ],
                'description' => $this->l('This web application firewall helps to protect your web applications against common web exploits that may affect availability, compromise security, or consume excessive resources. It makes your applications secure by enabling security rules that block common attack patterns, such as SQL injection, cross-site scripting, etc.') . ' ' . $this->l('Once you have configured the firewall, remember to test that everything works normally in your front office.') . ' ' . $this->generateLink('https://en.wikipedia.org/wiki/Web_application_firewall', $this->l('Read more')) . '.',
                'input' => [
                    [
                        'type' => 'switch',
                        'col' => 8,
                        'label' => $this->l('DDoS protection'),
                        'name' => 'LITE_ANTI_FLOOD',
                        'disabled' => true,
                        'is_bool' => true,
                        'desc' => $this->proFeature . $this->l('Anti-flood/DDoS protection. This feature is great for preventing most DDoS attacks and automatic multiple requests.') . ' ' . $this->generateLink('https://en.wikipedia.org/wiki/Denial-of-service_attack', $this->l('Read more')) . '.',
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
                        'col' => 4,
                        'type' => 'text',
                        'suffix' => $this->l('requests'),
                        'prefix' => '<i class="icon-repeat"></i>',
                        'desc' => $this->proFeature . $this->l('Allowed page requests for the user.') . ' ' . $this->l('The default value is') . ' 100.',
                        'name' => 'LITE_ANTI_MAX_REQUESTS',
                        'label' => $this->l('Max requests'),
                        'hint' => $this->l('Must be an integer'),
                        'required' => true,
                        'disabled' => true,
                    ],
                    [
                        'col' => 4,
                        'type' => 'text',
                        'suffix' => $this->l('seconds'),
                        'prefix' => '<i class="icon-clock-o"></i>',
                        'desc' => $this->proFeature . $this->l('Time interval to start counting page requests.') . ' ' . $this->l('The default value is') . ' 5.',
                        'name' => 'LITE_ANTI_REQ_TIMEOUT',
                        'label' => $this->l('Request timeout'),
                        'hint' => $this->l('Must be an integer'),
                        'required' => true,
                        'disabled' => true,
                    ],
                    [
                        'col' => 4,
                        'type' => 'text',
                        'suffix' => $this->l('seconds'),
                        'prefix' => '<i class="icon-clock-o"></i>',
                        'desc' => $this->proFeature . $this->l('Time to punish the user who has exceeded in doing requests.') . ' ' . $this->l('The default value is') . ' 600.',
                        'name' => 'LITE_ANTI_BAN_TIME',
                        'label' => $this->l('Ban time'),
                        'hint' => $this->l('Must be an integer'),
                        'required' => true,
                        'disabled' => true,
                    ],
                    [
                        'type' => 'switch',
                        'col' => 8,
                        'label' => $this->l('Honeypot bot check'),
                        'name' => 'LITE_FIREWALL_CHECK_BOT',
                        'is_bool' => true,
                        'disabled' => true,
                        'desc' => $this->proFeature . $this->l('The honeypot project has a big database of bad bots/spammers. If this feature is enabled, the module will look up the IP of clients accessing your site against this database. If there is a match, the client will need to solve a reCAPTCHA to continue using the website. Search engines are excluded from this check.') . ' ' . $this->generateLink('https://www.projecthoneypot.org/about_us.php', $this->l('Read more')) . '.',
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
                        'type' => 'select',
                        'col' => 8,
                        'label' => $this->l('Anti-SQL injection'),
                        'name' => 'LITE_FIREWALL_SQL_CHECK',
                        'desc' => $this->proFeature . $this->l('SQL injection is a web security vulnerability that allows an attacker to interfere with the queries that an application makes to its database.') . ' ' . $this->l('If the request looks like an attack, choose whether the client can proceed after solving a challenge (reCAPTCHA v2), get blocked (403) or get redirected to \'page not found\' (404).') . ' ' . $this->generateLink('https://owasp.org/www-community/attacks/SQL_Injection', $this->l('Read more')) . '.',
                        'disabled' => true,
                        'options' => [
                            'query' => [
                                [
                                    'id_option' => 0,
                                    'name' => $this->l('Disabled'),
                                ],
                                [
                                    'id_option' => 1,
                                    'name' => $this->l('Block request (403)'),
                                ],
                                [
                                    'id_option' => 2,
                                    'name' => $this->l('Page-not-found (404)'),
                                ],
                                [
                                    'id_option' => 3,
                                    'name' => $this->l('Challenge (reCAPTCHA v2)'),
                                ],
                            ],
                            'id' => 'id_option',
                            'name' => 'name',
                        ],
                    ],
                    [
                        'type' => 'select',
                        'col' => 8,
                        'label' => $this->l('Anti XXS injection'),
                        'name' => 'LITE_FIREWALL_XXS_CHECK',
                        'disabled' => true,
                        'desc' => $this->proFeature . $this->l('XSS (Cross-Site Scripting) injection is a web security vulnerability that allows an attacker to inject code (basically client-side scripting) to the remote server.') . ' ' . $this->l('If the request looks like an attack, choose whether the client can proceed after solving a challenge (reCAPTCHA v2), get blocked (403) or get redirected to \'page not found\' (404).') . ' ' . $this->generateLink('https://owasp.org/www-community/attacks/xss/', $this->l('Read more')) . '.',
                        'options' => [
                            'query' => [
                                [
                                    'id_option' => 0,
                                    'name' => $this->l('Disabled'),
                                ],
                                [
                                    'id_option' => 1,
                                    'name' => $this->l('Block (403)'),
                                ],
                                [
                                    'id_option' => 2,
                                    'name' => $this->l('Page-not-found (404)'),
                                ],
                                [
                                    'id_option' => 3,
                                    'name' => 'Challenge (reCAPTCHA v2)',
                                ],
                            ],
                            'id' => 'id_option',
                            'name' => 'name',
                        ],
                    ],
                    [
                        'type' => 'select',
                        'col' => 8,
                        'label' => $this->l('Anti command injection'),
                        'name' => 'LITE_FIREWALL_SHELL_CHECK',
                        'disabled' => true,
                        'desc' => $this->proFeature . $this->l('Command injection is a web security vulnerability that allows an attacker to inject code into the remote server.') . ' ' . $this->l('If the request looks like an attack, choose whether the client can proceed after solving a challenge (reCAPTCHA v2), get blocked (403) or get redirected to \'page not found\' (404).') . ' ' . $this->generateLink('https://owasp.org/www-community/attacks/Command_Injection', $this->l('Read more')) . '.',
                        'options' => [
                            'query' => [
                                [
                                    'id_option' => 0,
                                    'name' => $this->l('Disabled'),
                                ],
                                [
                                    'id_option' => 1,
                                    'name' => $this->l('Block request (403)'),
                                ],
                                [
                                    'id_option' => 2,
                                    'name' => $this->l('Page-not-found (404)'),
                                ],
                                [
                                    'id_option' => 3,
                                    'name' => 'challenge (reCAPTCHA v2)',
                                ],
                            ],
                            'id' => 'id_option',
                            'name' => 'name',
                        ],
                    ],
                    [
                        'type' => 'switch',
                        'col' => 8,
                        'label' => $this->l('RFI protection'),
                        'name' => 'LITE_FIREWALL_RFI_CHECK',
                        'is_bool' => true,
                        'disabled' => true,
                        'desc' => $this->proFeature . $this->l('Remote file inclusion (RFI) is an attack targeting vulnerabilities in web applications that dynamically reference external scripts. Block the request if the request looks like an RFI attack.') . ' ' . $this->l('This feature is for advanced users. Watch the firewall log if you enable this feature, in case you have installed a third-party module that gets blocked by this feature due to the design of the request.') . ' ' . $this->generateLink('https://owasp.org/www-community/vulnerabilities/PHP_File_Inclusion', $this->l('Read more')) . '.',
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
                        'col' => 8,
                        'label' => $this->l('XST protection'),
                        'name' => 'LITE_FIREWALL_XST_CHECK',
                        'is_bool' => true,
                        'disabled' => true,
                        'desc' => $this->proFeature . $this->l('Cross-Site Tracing (XST) is a network security vulnerability exploiting the HTTP TRACE method. Enable this option to block HTTP TRACK and HTTP TRACE requests.') . ' ' . $this->generateLink('https://en.wikipedia.org/wiki/Cross-site_tracing', $this->l('Read more')) . '.',
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
                        'col' => 8,
                        'label' => $this->l('Block TOR IPv4 and IPv6 addresses'),
                        'name' => 'LITE_BLOCK_TOR',
                        'is_bool' => true,
                        'desc' => $this->l('In some cases, TOR browsers are used by criminals to hide while buying from a stolen credit card. If you are having this problem, you can block TOR IPv4 and IPv6 addresses with this feature.') . ' ' . $this->generateLink('https://en.wikipedia.org/wiki/Tor_(anonymity_network)', $this->l('Read more')) . '.',
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
                        'col' => 8,
                        'label' => $this->l('Block directory traversal'),
                        'name' => 'LITE_DIR_TRAVERSAL',
                        'is_bool' => true,
                        'disabled' => true,
                        'desc' => $this->proFeature . $this->l('Directory traversal attacks use the webserver software to exploit inadequate security mechanisms and access directories and files stored outside of the webroot folder. This option protects against traversal attacks.') . ' ' . $this->generateLink('https://en.wikipedia.org/wiki/Directory_traversal_attack', $this->l('Read more')) . '.',
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
                        'col' => 8,
                        'label' => $this->l('Block too long HTTP requests'),
                        'name' => 'LITE_FIREWALL_CHECK_REQUEST',
                        'is_bool' => true,
                        'disabled' => true,
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
                        'type' => 'switch',
                        'col' => 8,
                        'label' => $this->l('Block user agents with too long names'),
                        'name' => 'LITE_FIREWALL_CHECK_USERAGENT',
                        'is_bool' => true,
                        'desc' => $this->proFeature . $this->l('Block the request if the user agent name is more than 472 characters.'),
                        'disabled' => true,
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
                        'type' => 'select',
                        'col' => 8,
                        'label' => $this->l('Block custom list of IP addresses'),
                        'name' => 'LITE_BAN_IP_ACTIVATE',
                        'desc' => $this->l('Block hosts with below IP addresses from your website. You cannot block hosts that are already on this') . ' ' . $this->generateLink($this->getAdminLink('AdminGeolocation', true), $this->l('whitelist')) . '. ' . $this->l('If you want to ban a country, please use this built-in PrestaShop feature') . ': ' . $this->generateLink($this->getAdminLink('AdminGeolocation', true), $this->l('Ban countries')) . '. ' . $this->l('It is generally not recommended to block countries. Blocking countries could lockout customers that are using a VPN or customers that are on vacation, etc.') . ' ' . $this->l('If the client is on the blacklist, choose whether the client can proceed after solving a challenge (reCAPTCHA v2) or get blocked (403).'),
                        'options' => [
                            'query' => [
                                [
                                    'id_option' => 0,
                                    'name' => $this->l('Disabled'),
                                ],
                                [
                                    'id_option' => 1,
                                    'name' => $this->l('Block request (403)'),
                                ],
                                [
                                    'id_option' => 3,
                                    'name' => $this->l('Challenge (reCAPTCHA v2)'),
                                ],
                            ],
                            'id' => 'id_option',
                            'name' => 'name',
                        ],
                    ],
                    [
                        'type' => 'textarea',
                        'col' => 8,
                        'desc' => $this->l('The module can handle IPv4 and IPv6 addresses, as well as IP ranges, in CIDR formats like') . ' <code>::1/128</code> ' . $this->l('or') . ' <code>127.0.0.1/32</code> ' . $this->l('and pattern format like') . ' <code>::*:*</code> ' . $this->l('or') . ' <code>127.0.*.*</code>. ' . $this->l('Separates by a comma') . ' (\',\') ' . $this->l('without space.'),
                        'name' => 'LITE_BAN_IP',
                        'label' => $this->l('Custom list of IP addresses'),
                        'hint' => $this->l('E.g.') . ' 123.456.789,123.456.*,123.*,...',
                    ],
                    [
                        'type' => 'select',
                        'col' => 8,
                        'label' => $this->l('Block custom list of user agents'),
                        'name' => 'LITE_BLOCK_USER_AGENT_ACTIVATE',
                        'is_bool' => true,
                        'desc' => $this->l('Block user agents with the below names from your website.'),
                        'options' => [
                            'query' => [
                                [
                                    'id_option' => 0,
                                    'name' => $this->l('Disabled'),
                                ],
                                [
                                    'id_option' => 1,
                                    'name' => $this->l('Block request (403)'),
                                ],
                                [
                                    'id_option' => 3,
                                    'name' => $this->l('Challenge (reCAPTCHA v2)'),
                                ],
                            ],
                            'id' => 'id_option',
                            'name' => 'name',
                        ],
                    ],
                    [
                        'type' => 'textarea',
                        'col' => 8,
                        'desc' => $this->l('Separates by a comma') . ' (\',\') ' . $this->l('without space.'),
                        'name' => 'LITE_BLOCK_USER_AGENT',
                        'label' => $this->l('Custom list of User agents'),
                        'hint' => $this->l('E.g.') . ' 360Spider,Alexibot,BackWeb,...',
                    ],
                    [
                        'type' => 'switch',
                        'col' => 8,
                        'label' => $this->l('Block file-upload'),
                        'name' => 'LITE_BLOCK_FILE_UPLOAD',
                        'disabled' => true,
                        'is_bool' => true,
                        'desc' => $this->proFeature . $this->l('Block the ability to upload files in the front office. don\'t enable this if you are using the contact form or another front office module that has a file transfer function.'),
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
                        'col' => 8,
                        'label' => $this->l('Scan file on upload'),
                        'name' => 'LITE_BLOCK_SCAN_FILE_UPLOAD',
                        'is_bool' => true,
                        'disabled' => true,
                        'desc' => $this->proFeature . $this->l('Scan uploaded files in the front office for trojans, viruses, malware and, other threats and block the request if the file is suspicious.'),
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
                        'col' => 8,
                        'label' => $this->l('Log hacking attempts'),
                        'name' => 'LITE_FIREWALL_LOG',
                        'is_bool' => true,
                        'desc' => $this->l('Record hacking attempts into a log file.') . ' ' . $this->l('This is recommended.'),
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
                        'type' => 'textbutton',
                        'col' => 8,
                        'desc' => $this->l('Whitelist IP addresses that should not be should be blocked by the firewall.') . '<br>' . $this->l('The module can handle IPv4 and IPv6 addresses, as well as IP ranges, in CIDR formats like') . ' <code>::1/128</code> ' . $this->l('or') . ' <code>127.0.0.1/32</code> ' . $this->l('and pattern format like') . ' <code>::*:*</code> ' . $this->l('or') . ' <code>127.0.*.*</code>. ' . $this->l('Separates by a comma') . ' (\',\') ' . $this->l('without space.'),
                        'name' => 'LITE_FIREWALL_WHITELIST',
                        'button' => [
                            'label' => '<i class="icon-plus"></i> ' . $this->l('Add my IP'),
                            'attributes' => [
                                'onclick' => 'addMyIp("#LITE_FIREWALL_WHITELIST");',
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
     * @return array
     */
    protected function fieldsFormProtectContent()
    {
        return [
            'form' => [
                'legend' => [
                    'title' => $this->l('Protect Content'),
                    'icon' => 'icon-hand-o-up',
                ],
                'description' => $this->l('The module allows you to disable a list of mouse- and key-events. These settings make it harder for users that manually try to steal your content. These settings will affect the front office only.'),
                'input' => [
                    [
                        'type' => 'select',
                        'label' => $this->l('Disable right-click'),
                        'desc' => $this->l('Disable right-click mouse event.') . ' ' . $this->l('Input and Textarea fields are excluded from this rule.'),
                        'name' => 'LITE_DISABLE_RIGHT_CLICK',
                        'options' => [
                            'query' => [
                                [
                                    'id_option' => 0,
                                    'name' => $this->l('No'),
                                ],
                                [
                                    'id_option' => 1,
                                    'name' => $this->l('Yes'),
                                ],
                                [
                                    'id_option' => 2,
                                    'name' => $this->l('Images only'),
                                ],
                            ],
                            'id' => 'id_option',
                            'name' => 'name',
                        ],
                    ],
                    [
                        'type' => 'switch',
                        'col' => 8,
                        'label' => $this->l('Disable drag and drop'),
                        'name' => 'LITE_DISABLE_DRAG',
                        'is_bool' => true,
                        'disabled' => true,
                        'desc' => $this->proFeature . $this->l('Disable drag and drop mouse event.') . ' ' . $this->l('Input and Textarea fields are excluded from this rule.'),
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
                        'col' => 8,
                        'label' => $this->l('Disable copy'),
                        'name' => 'LITE_DISABLE_COPY',
                        'is_bool' => true,
                        'disabled' => true,
                        'desc' => $this->proFeature . $this->l('Disable copy (E.g. Ctrl + c / ⌘ + c).') . ' ' . $this->l('Input and Textarea fields are excluded from this rule.'),
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
                        'col' => 8,
                        'label' => $this->l('Disable cut'),
                        'name' => 'LITE_DISABLE_CUT',
                        'is_bool' => true,
                        'disabled' => true,
                        'desc' => $this->proFeature . $this->l('Disable cut (E.g. Ctrl + x / ⌘ + x).') . ' ' . $this->l('Input and Textarea fields are excluded from this rule.'),
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
                        'col' => 8,
                        'label' => $this->l('Disable paste'),
                        'name' => 'LITE_DISABLE_PASTE',
                        'is_bool' => true,
                        'disabled' => true,
                        'desc' => $this->proFeature . $this->l('Disable paste (E.g. Ctrl + v / ⌘ + v).') . ' ' . $this->l('Input and Textarea fields are excluded from this rule.'),
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
                        'col' => 8,
                        'label' => $this->l('Disable text selection'),
                        'name' => 'LITE_DISABLE_TEXT_SELECTION',
                        'is_bool' => true,
                        'disabled' => true,
                        'desc' => $this->proFeature . $this->l('Disable text selection') . '. ' . $this->l('Input and Textarea fields are excluded from this rule.'),
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
                        'col' => 8,
                        'label' => $this->l('Disable print'),
                        'name' => 'LITE_DISABLE_PRINT',
                        'is_bool' => true,
                        'disabled' => true,
                        'desc' => $this->proFeature . $this->l('Disable print (E.g. Ctrl + p / ⌘ + p).'),
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
                        'col' => 8,
                        'label' => $this->l('Disable save'),
                        'name' => 'LITE_DISABLE_SAVE',
                        'is_bool' => true,
                        'disabled' => true,
                        'desc' => $this->proFeature . $this->l('Disable save (E.g. Ctrl + s / ⌘ + s).'),
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
                        'col' => 8,
                        'label' => $this->l('Disable developer tool hotkeys'),
                        'name' => 'LITE_DISABLE_VIEW_PAGE_SOURCE',
                        'is_bool' => true,
                        'disabled' => true,
                        'desc' => $this->proFeature . $this->l('Disable developer tool hotkeys') . '.',
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
                        'col' => 8,
                        'label' => $this->l('Disable console'),
                        'name' => 'LITE_DISABLE_CONSOLE',
                        'is_bool' => true,
                        'disabled' => true,
                        'desc' => $this->proFeature . $this->l('Disable console') . '.',
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
                        'col' => 8,
                        'type' => 'textbutton',
                        'label' => $this->l('Whitelist'),
                        'hint' => $this->l('E.g.') . ' 123.456.789,123.456.*,123.*,...',
                        'desc' => $this->l('You can list your IP addresses if you want to bypass your rules above.') . '<br>' . $this->l('The module can handle IPv4 and IPv6 addresses, as well as IP ranges, in CIDR formats like') . ' <code>::1/128</code> ' . $this->l('or') . ' <code>127.0.0.1/32</code> ' . $this->l('and pattern format like') . ' <code>::*:*</code> ' . $this->l('or') . ' <code>127.0.*.*</code>. ' . $this->l('Separates by a comma') . ' (\',\') ' . $this->l('without space.'),
                        'name' => 'LITE_WHITELIST_PROTECT_CONTENT',
                        'button' => [
                            'label' => '<i class="icon-plus"></i> ' . $this->l('Add my IP'),
                            'attributes' => [
                                'onclick' => 'addMyIp("#LITE_WHITELIST_PROTECT_CONTENT");',
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

    /**
     * @return array
     */
    protected function fieldsFormPasswordStrengh()
    {
        return [
            'form' => [
                'legend' => [
                    'title' => $this->l('Password Strength'),
                    'icon' => 'icon-tasks',
                ],
                'input' => [
                    [
                        'type' => 'switch',
                        'col' => 8,
                        'label' => $this->l('Password strength meter'),
                        'name' => 'LITE_PASSWORD_STRENGHTBAR',
                        'is_bool' => true,
                        'disabled' => true,
                        'desc' => $this->proFeature . $this->l('Add a meter under the password field giving your customers instant feedback on the strength of their passwords, thus giving your customers a more secure shopping experience.'),
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

    /**
     * @return array
     */
    protected function fieldsFormAntiFraud()
    {
        return [
            'form' => [
                'legend' => [
                    'title' => $this->l('Fraud Detection'),
                    'icon' => 'icon-user-times',
                ],
                'description' => $this->l('The module can analyze your orders on different criteria. A score is established to determine whether the order looks suspicious or not.'),
                'input' => [
                    [
                        'type' => 'switch',
                        'col' => 8,
                        'label' => $this->l('Fraud detection'),
                        'name' => 'LITE_ANTI_FRAUD',
                        'is_bool' => true,
                        'disabled' => true,
                        'desc' => $this->proFeature . $this->l('Display a section on each order, that tells if the order looks suspicious.'),
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
                        'type' => 'select',
                        'label' => $this->l('Distance unit'),
                        'desc' => $this->proFeature . $this->l('Choose your default distance unit. \'km\' for kilometer, \'mi\' for mile.'),
                        'name' => 'LITE_ANTI_FRAUD_UNIT',
                        'disabled' => true,
                        'options' => [
                            'query' => [
                                [
                                    'id_option' => 'km',
                                    'name' => 'km',
                                ],
                                [
                                    'id_option' => 'mi',
                                    'name' => 'mi',
                                ],
                            ],
                            'id' => 'id_option',
                            'name' => 'name',
                        ],
                    ],
                    [
                        'type' => 'select',
                        'label' => $this->l('Display'),
                        'desc' => $this->proFeature . $this->l('Choose where you want to display the section at the admin order page.'),
                        'disabled' => true,
                        'name' => 'LITE_ANTI_FRAUD_HOOK',
                        'options' => [
                            'query' => [
                                [
                                    'id_option' => 'left',
                                    'name' => $this->l('Left column'),
                                ],
                                [
                                    'id_option' => 'right',
                                    'name' => $this->l('Right column'),
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
     *
     * @return array
     */
    protected function fieldsFormTwoFactorAuth()
    {
        $tfa = new \RobThree\Auth\TwoFactorAuth(Configuration::get('PS_SHOP_NAME'), 6, 30, 'sha1');
        $content = \Tools::substr(\mb_strtoupper($this->encrypt('2fa-recovery')), 0, 12);

        $twoFactorAuth = [
            $this->l('Download a 2FA app on your phone') . ': <strong>Google Authenticator</strong>, <strong>Microsoft Authenticator</strong>, ' . $this->l('or any app supporting the TOTP algorithm.'),
            $this->l('Open the app and scan the QR code below') . ':<br><img src="' . $tfa->getQRCodeImageAsDataUri('Admin', $this->getSecret()) . '" alt="" loading="lazy">',
            $this->l('If you for some reason cannot scan the QR-code, you can use this code for manual input instead') . ': <strong>' . Tools::substr(\chunk_split($this->getSecret(), 4, ' '), 0, -1) . '</strong>',
            $this->l('Insert the code you see on your phone in the code field below to verify that everything is working.'),
            $this->l('Save settings in the module, before the code expires.'),
        ];

        $employees = $this->getEmployees(true);

        $tfaLinks = [];
        foreach ($employees as $employee) {
            $tfaLinks[] = [
                $this->l('Name') => $employee['firstname'] . ' ' . $employee['lastname'],
                $this->l('E-mail') => $employee['email'],
                $this->l('Link') => '<kbd>' . $this->getAdminLink('AdminLogin', true) . '&2fa=' . \htmlentities($this->encrypt($employee['passwd'])) . '</kbd>',
            ];
        }

        $result = $this->addAlertInfo($this->l('If any of your employees need the ability to skip the two-factor authentication, then they can use the links below. These links have an extra parameter in the login URL. When accessing this link, the two-factor authentication is skipped.')) . $this->addAlertWarning($this->l('Important information for the webmaster') . ': ' . $this->l('The 2FA-token is linked to the password of the employee, so if the employee resets his login-password, the TFA-token will change as well due to security reasons.')) . $this->arrayToTable($tfaLinks);

        return [
            'form' => [
                'legend' => [
                    'title' => $this->l('Two-Factor Authentication'),
                    'icon' => 'icon-key',
                ],
                'description' => $this->l('Two-factor authentication is an extra layer of security for your PrestaShop admin panel, designed to make sure that you\'re the only person who can get access to your back office, even if someone knows your password.') . ' ' . $this->generateLink('https://en.wikipedia.org/wiki/Multi-factor_authentication', $this->l('Read more')) . '.',
                'warning' => $this->l('Please write down and store this 12-character recovery code somewhere safe. In case you lose access to your device, you can use this code to pass the 2FA-step') . ': <kbd>' . Tools::substr(\chunk_split($content, 4, ' '), 0, -1) . '</kbd> <a href="javascript:void(0)" onclick="copyToClipboard(\'' . $content . '\')"><i class="icon icon-clipboard"></i></a>',
                'input' => [
                    [
                        'type' => 'switch',
                        'col' => 8,
                        'label' => $this->l('Two-Factor Authentication'),
                        'name' => 'LITE_TWO_FACTOR_AUTH',
                        'is_bool' => true,
                        'desc' => $this->proFeature . '</p><ol class="help-block"><li>' . \implode('</li><li>', $twoFactorAuth) . '</li></ol><p>',
                        'disabled' => true,
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
                        'col' => 4,
                        'type' => 'text',
                        'prefix' => '<i class="icon-key"></i>',
                        'desc' => $this->proFeature . $this->l('To confirm that everything is correct, you must enter your code from your app before you save settings.'),
                        'name' => 'LITE_TWO_FACTOR_AUTH_CODE',
                        'label' => $this->l('Code'),
                        'hint' => $this->l('Must be 6 digitals'),
                        'disabled' => $this->proFeature . $this->getTwoFactorAuthDB('enabled') ? true : false,
                        'required' => true,
                        'disabled' => true,
                    ],
                    [
                        'type' => 'textbutton',
                        'col' => 8,
                        'desc' => $this->proFeature . $this->l('You can list your IP addresses if you want to skip the Two-Factor Authentication when you are on a specific network.') . '<br>' . $this->l('The module can handle IPv4 and IPv6 addresses, as well as IP ranges, in CIDR formats') . $this->l('like') . ' <code>::1/128</code> ' . $this->l('or') . ' <code>127.0.0.1/32</code> ' . $this->l('and pattern format like') . ' <code>::*:*</code> ' . $this->l('or') . ' <code>127.0.*.*</code>. ' . $this->l('Separates by a comma') . ' (\',\') ' . $this->l('without space.'),
                        'name' => 'LITE_TWO_FACTOR_AUTH_WHITELIST',
                        'button' => [
                            'label' => '<i class="icon-plus"></i> ' . $this->l('Add my IP'),
                            'attributes' => [
                                'onclick' => '',
                            ],
                        ],
                        'label' => $this->l('Whitelist IP addresses'),
                        'hint' => $this->l('E.g.') . ' 123.456.789,123.456.*,123.*,...',
                        'disabled' => true,
                    ],
                    [
                        'type' => 'html',
                        'label' => '',
                        'html_content' => $result,
                        'col' => 12,
                        'name' => '',
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
     *
     * @return array
     */
    protected function getConfigFormValues()
    {
        return [
            'LITE_GENERAL_EMAIL' => Configuration::get('LITE_GENERAL_EMAIL'),
            'LITE_CLICK_JACKING' => Configuration::get('LITE_CLICK_JACKING'),
            'LITE_X_XSS_PPROTECTION' => Configuration::get('LITE_X_XSS_PPROTECTION'),
            'LITE_X_CONTENT_TYPE_OPTIONS' => Configuration::get('LITE_X_CONTENT_TYPE_OPTIONS'),
            'LITE_STRICT_TRANSPORT_SECURITY' => Configuration::get('LITE_STRICT_TRANSPORT_SECURITY'),
            'LITE_HSTS_SETTINGS_0' => Configuration::get('LITE_HSTS_SETTINGS_0'),
            'LITE_HSTS_SETTINGS_1' => Configuration::get('LITE_HSTS_SETTINGS_1'),
            'LITE_EXPECT_CT' => Configuration::get('LITE_EXPECT_CT'),
            'LITE_ACCESS_CONTROL_ALLOW_METHODS' => Configuration::get('LITE_ACCESS_CONTROL_ALLOW_METHODS'),
            'LITE_REFFERER_POLICY' => Configuration::get('LITE_REFFERER_POLICY'),
            'LITE_X_PERITTED_CROSS_DOMAIN_POLICY' => Configuration::get('LITE_X_PERITTED_CROSS_DOMAIN_POLICY'),
            'LITE_X_DOWNLOAD_OPTIONS' => Configuration::get('LITE_X_DOWNLOAD_OPTIONS'),
            'LITE_UNSET_HEADERS' => Configuration::get('LITE_UNSET_HEADERS'),
            'LITE_HTPASSWD' => Configuration::get('LITE_HTPASSWD'),
            'LITE_HTPASSWD_USER' => Configuration::get('LITE_HTPASSWD_USER'),
            'LITE_HTPASSWD_PASS' => Configuration::get('LITE_HTPASSWD_PASS'),
            'LITE_BAN_IP' => Configuration::get('LITE_BAN_IP'),
            'LITE_BAN_IP_ACTIVATE' => Configuration::get('LITE_BAN_IP_ACTIVATE'),
            'LITE_FAIL2BAN' => Configuration::get('LITE_FAIL2BAN'),
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
            'LITE_DISABLE_RIGHT_CLICK' => Configuration::get('LITE_DISABLE_RIGHT_CLICK'),
            'LITE_DISABLE_DRAG' => Configuration::get('LITE_DISABLE_DRAG'),
            'LITE_DISABLE_COPY' => Configuration::get('LITE_DISABLE_COPY'),
            'LITE_DISABLE_CUT' => Configuration::get('LITE_DISABLE_CUT'),
            'LITE_DISABLE_PRINT' => Configuration::get('LITE_DISABLE_PRINT'),
            'LITE_DISABLE_SAVE' => Configuration::get('LITE_DISABLE_SAVE'),
            'LITE_DISABLE_VIEW_PAGE_SOURCE' => Configuration::get('LITE_DISABLE_VIEW_PAGE_SOURCE'),
            'LITE_DISABLE_CONSOLE' => Configuration::get('LITE_DISABLE_CONSOLE'),
            'LITE_DISABLE_PASTE' => Configuration::get('LITE_DISABLE_PASTE'),
            'LITE_DISABLE_TEXT_SELECTION' => Configuration::get('LITE_DISABLE_TEXT_SELECTION'),
            'LITE_ADMIN_DIRECTORY' => Configuration::get('LITE_ADMIN_DIRECTORY'),
            'LITE_ADMIN_DIRECTORY_NAME' => Configuration::get('LITE_ADMIN_DIRECTORY_NAME'),
            'LITE_BACKUP_DB_TOKEN' => Configuration::get('LITE_BACKUP_DB_TOKEN'),
            'LITE_BLOCK_ADD_TO_CART' => Configuration::get('LITE_BLOCK_ADD_TO_CART'),
            'LITE_DELETE_OLD_CARTS' => Configuration::get('LITE_DELETE_OLD_CARTS'),
            'LITE_DELETE_OLD_CARTS_DAYS' => Configuration::get('LITE_DELETE_OLD_CARTS_DAYS'),
            'LITE_ANTI_FLOOD' => Configuration::get('LITE_ANTI_FLOOD'),
            'LITE_ANTI_MAX_REQUESTS' => (int) Configuration::get('LITE_ANTI_MAX_REQUESTS'),
            'LITE_ANTI_REQ_TIMEOUT' => (int) Configuration::get('LITE_ANTI_REQ_TIMEOUT'),
            'LITE_ANTI_BAN_TIME' => (int) Configuration::get('LITE_ANTI_BAN_TIME'),
            'LITE_FIREWALL_RECAPTCHA_SECRET' => Configuration::get('LITE_FIREWALL_RECAPTCHA_SECRET'),
            'LITE_FIREWALL_RECAPTCHA_SITE_KEY' => Configuration::get('LITE_FIREWALL_RECAPTCHA_SITE_KEY'),
            'LITE_RECAPTCHA_V3_SECRET' => Configuration::get('LITE_RECAPTCHA_V3_SECRET'),
            'LITE_RECAPTCHA_V3_SITE_KEY' => Configuration::get('LITE_RECAPTCHA_V3_SITE_KEY'),
            'LITE_DISPLAY_RECAPTCHA_V3' => Configuration::get('LITE_DISPLAY_RECAPTCHA_V3'),
            'LITE_GOOGLE_SAFE_BROWSING_V4_API' => Configuration::get('LITE_GOOGLE_SAFE_BROWSING_V4_API'),
            'LITE_GOOGLE_SAFE_BROWSING_V4_ACTIVATE' => Configuration::get('LITE_GOOGLE_SAFE_BROWSING_V4_ACTIVATE'),
            'LITE_DISPOSABLE_EMAIL_PROVIDERS_ACTIVATE' => Configuration::get('LITE_DISPOSABLE_EMAIL_PROVIDERS_ACTIVATE'),
            'LITE_DISPOSABLE_EMAIL_PROVIDERS_REGISTRATION_ACTIVATE' => Configuration::get('LITE_DISPOSABLE_EMAIL_PROVIDERS_REGISTRATION_ACTIVATE'),
            'LITE_EMAIL_CHECKER_REGISTRATION_ACTIVATE' => Configuration::get('LITE_EMAIL_CHECKER_REGISTRATION_ACTIVATE'),
            'LITE_EMAIL_CHECKER_CUSTOM_LIST_REGISTRATION' => Configuration::get('LITE_EMAIL_CHECKER_CUSTOM_LIST_REGISTRATION'),
            'LITE_EMAIL_CHECKER_ACTIVATE' => Configuration::get('LITE_EMAIL_CHECKER_ACTIVATE'),
            'LITE_EMAIL_CHECKER_CUSTOM_LIST' => Configuration::get('LITE_EMAIL_CHECKER_CUSTOM_LIST'),
            'LITE_MESSAGE_CHECKER_ACTIVATE' => Configuration::get('LITE_MESSAGE_CHECKER_ACTIVATE'),
            'LITE_MESSAGE_CHECKER_CUSTOM_LIST' => Configuration::get('LITE_MESSAGE_CHECKER_CUSTOM_LIST'),
            'LITE_HONEYPOT_API' => Configuration::get('LITE_HONEYPOT_API'),
            'LITE_MONTASTIC_API' => Configuration::get('LITE_MONTASTIC_API'),
            'LITE_FIREWALL_CHECK_BOT' => Configuration::get('LITE_FIREWALL_CHECK_BOT'),
            'LITE_FIREWALL_SQL_CHECK' => Configuration::get('LITE_FIREWALL_SQL_CHECK'),
            'LITE_FIREWALL_XXS_CHECK' => Configuration::get('LITE_FIREWALL_XXS_CHECK'),
            'LITE_FIREWALL_SHELL_CHECK' => Configuration::get('LITE_FIREWALL_SHELL_CHECK'),
            'LITE_FIREWALL_XST_CHECK' => Configuration::get('LITE_FIREWALL_XST_CHECK'),
            'LITE_DIR_TRAVERSAL' => Configuration::get('LITE_DIR_TRAVERSAL'),
            'LITE_FIREWALL_RFI_CHECK' => Configuration::get('LITE_FIREWALL_RFI_CHECK'),
            'LITE_FIREWALL_CHECK_REQUEST' => Configuration::get('LITE_FIREWALL_CHECK_REQUEST'),
            'LITE_FIREWALL_CHECK_USERAGENT' => Configuration::get('LITE_FIREWALL_CHECK_USERAGENT'),
            'LITE_BLOCK_FILE_UPLOAD' => Configuration::get('LITE_BLOCK_FILE_UPLOAD'),
            'LITE_BLOCK_SCAN_FILE_UPLOAD' => Configuration::get('LITE_BLOCK_SCAN_FILE_UPLOAD'),
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
            'LITE_FIREWALL_WHITELIST' => Configuration::get('LITE_FIREWALL_WHITELIST'),
            'LITE_FAKE_ACCOUNTS' => Configuration::get('LITE_FAKE_ACCOUNTS'),
            'LITE_DISALLOW_URL_CUSTOMER_NAME' => Configuration::get('LITE_DISALLOW_URL_CUSTOMER_NAME'),
            'LITE_WHITELIST_PROTECT_CONTENT' => Configuration::get('LITE_WHITELIST_PROTECT_CONTENT'),
            'LITE_BLOCK_USER_AGENT_ACTIVATE' => Configuration::get('LITE_BLOCK_USER_AGENT_ACTIVATE'),
            'LITE_BLOCK_USER_AGENT' => Configuration::get('LITE_BLOCK_USER_AGENT'),
            'LITE_BLOCK_TOR' => Configuration::get('LITE_BLOCK_TOR'),
            'LITE_DISABLE_CONTACT_FORM' => Configuration::get('LITE_DISABLE_CONTACT_FORM'),
            'LITE_RECAPTCHA_V3_CONTACT_ACTIVATE' => Configuration::get('LITE_RECAPTCHA_V3_CONTACT_ACTIVATE'),
            'LITE_RECAPTCHA_V3_REGISTRATION_ACTIVATE' => Configuration::get('LITE_RECAPTCHA_V3_REGISTRATION_ACTIVATE'),
            'LITE_RECAPTCHA_V3_THEME' => Configuration::get('LITE_RECAPTCHA_V3_THEME'),
            'LITE_PAGE_NOT_FOUND_LOG' => Configuration::get('LITE_PAGE_NOT_FOUND_LOG'),
            'LITE_PASSWORD_STRENGHTBAR' => Configuration::get('LITE_PASSWORD_STRENGHTBAR'),
            'LITE_ANTI_FRAUD' => Configuration::get('LITE_ANTI_FRAUD'),
            'LITE_ANTI_FRAUD_UNIT' => Configuration::get('LITE_ANTI_FRAUD_UNIT'),
            'LITE_ANTI_FRAUD_HOOK' => Configuration::get('LITE_ANTI_FRAUD_HOOK'),
            'LITE_SERVER_IP' => Configuration::get('LITE_SERVER_IP'),
            'LITE_SERVER_LOCATION' => Configuration::get('LITE_SERVER_LOCATION'),
            'LITE_SERVER_ISP' => Configuration::get('LITE_SERVER_ISP'),
            'LITE_DOMAIN_EXPIRE' => Configuration::get('LITE_DOMAIN_EXPIRE'),
            'LITE_TLS_EXPIRE' => Configuration::get('LITE_TLS_EXPIRE'),
            'LITE_STEALTH_LOGIN' => Configuration::get('LITE_STEALTH_LOGIN'),
            'LITE_STEALTH_LOGIN_WHITELIST' => Configuration::get('LITE_STEALTH_LOGIN_WHITELIST'),
            'LITE_ADVANCED_MAINTENANCE_MODE' => Configuration::get('LITE_ADVANCED_MAINTENANCE_MODE'),
            'LITE_ADVANCED_MAINTENANCE_MODE_COMPANY' => Configuration::get('LITE_ADVANCED_MAINTENANCE_MODE_COMPANY'),
            'LITE_ADVANCED_MAINTENANCE_MODE_ADDRESS' => Configuration::get('LITE_ADVANCED_MAINTENANCE_MODE_ADDRESS'),
            'LITE_ADVANCED_MAINTENANCE_MODE_PHONE' => Configuration::get('LITE_ADVANCED_MAINTENANCE_MODE_PHONE'),
            'LITE_ADVANCED_MAINTENANCE_MODE_EMAIL' => Configuration::get('LITE_ADVANCED_MAINTENANCE_MODE_EMAIL'),
            'LITE_ADVANCED_MAINTENANCE_MODE_FACEBOOK' => Configuration::get('LITE_ADVANCED_MAINTENANCE_MODE_FACEBOOK'),
            'LITE_ADVANCED_MAINTENANCE_MODE_TWITTER' => Configuration::get('LITE_ADVANCED_MAINTENANCE_MODE_TWITTER'),
            'LITE_ADVANCED_MAINTENANCE_MODE_INSTAGRAM' => Configuration::get('LITE_ADVANCED_MAINTENANCE_MODE_INSTAGRAM'),
            'LITE_ADVANCED_MAINTENANCE_MODE_PINTEREST' => Configuration::get('LITE_ADVANCED_MAINTENANCE_MODE_PINTEREST'),
            'LITE_ADVANCED_MAINTENANCE_MODE_YOUTUBE' => Configuration::get('LITE_ADVANCED_MAINTENANCE_MODE_YOUTUBE'),
            'LITE_ADVANCED_MAINTENANCE_MODE_COPYRIGHT' => Configuration::get('LITE_ADVANCED_MAINTENANCE_MODE_COPYRIGHT'),
            'LITE_ADVANCED_MAINTENANCE_MODE_LOGO' => Configuration::get('LITE_ADVANCED_MAINTENANCE_MODE_LOGO'),
            'LITE_ADVANCED_MAINTENANCE_MODE_LOGO_PATH' => Configuration::get('LITE_ADVANCED_MAINTENANCE_MODE_LOGO_PATH'),
            'LITE_DEBUG_CRON' => Configuration::get('LITE_DEBUG_CRON'),
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

    /**
     * @return array
     */
    protected function fieldsFormWebsiteMonitoringService()
    {
        $apiKey = (bool) Configuration::get('LITE_MONTASTIC_API');
        $result = null;
        if (true === ($apiKey)) {
            $ids = $this->getMontasticIds();
            if (!empty($ids)) {
                $yes = '<i class="icon icon-check" style="color: ' . self::COLOR_GREEN . '"></i>';
                $no = '<i class="icon icon-times" style="color: ' . self::COLOR_RED . '"></i>';
                $table = [];

                foreach ($ids as $id) {
                    $data = $this->getMontasticData($id);
                    $table[] = [
                        $this->l('Checkpoint') => $data['url'],
                        $this->l('Enabled') => ($data['is_monitoring_enabled']) ? $yes : $no,
                        $this->l('Monitoring interval') => $data['check_interval_id'] . ' ' . $this->l('min.'),
                        $this->l('Status') => (-1 !== $data['status']) ? $yes : $no,
                    ];
                }

                $result = $this->arrayToTable($table);
            }
        }

        return [
            'form' => [
                'legend' => [
                    'title' => $this->l('Website Monitoring Service'),
                    'icon' => 'icon-clock-o',
                ],
                'description' => $this->l('By connecting up with Montastic, you can be notified by e-mail if your website is down. The free plan allows you to ping your website(s) every 30 min. You can have up to 9 checkpoints at the same time. Try it out!') . '<br>' . $this->l('You can manage your checkpoints here') . ': ' . $this->generateLink('https://montastic.com/checkpoints') . '.',
                'warning' => (false === $apiKey) ? $this->l('You need to add your API key in \'General Settings\' to get access to this content. You can get an API key here at') . ' ' . $this->generateLink('https://montastic.com/me?tab=form_profile') . ' (' . $this->l('You can choose the free plan') . ').' : null,
                'input' => [
                    [
                        'type' => 'html',
                        'label' => '',
                        'html_content' => (null !== ($result)) ? $result : '',
                        'col' => 12,
                        'name' => '',
                    ],
                ],
            ],
        ];
    }

    /**
     * Return HTML code for display of favicon.
     */
    private function getFavicon()
    {
        $favicon = Configuration::get('PS_FAVICON');

        if (true === (bool) $favicon) {
            $faviconUpdateTime = Configuration::get('PS_IMG_UPDATE_TIME');

            return '<link rel="icon" type="image/vnd.microsoft.icon" href="' . _PS_IMG_ . $favicon . '?' . $faviconUpdateTime . '"> <link rel="shortcut icon" type="image/x-icon" href="' . _PS_IMG_ . $favicon . '?' . $faviconUpdateTime . '">';
        }
    }

    /**
     * Get Firewall.
     */
    private function getFirewall()
    {
        if (false === $this->validateGoogleBotIp()) {
            $ip = \Tools::getRemoteAddr();
            if (false === $this->checkWhitelist('LITE_FIREWALL_WHITELIST') && '54.243.46.120' !== $ip) {
                $this->googleRecaptchaCheck();

                // Anti-SPAM: Log 404 requests
                if (true === (bool) Configuration::get('LITE_PAGE_NOT_FOUND_LOG')) {
                    if ('pagenotfound' === Tools::getValue('controller')) {
                        if (false === \strpos($_SERVER['REQUEST_URI'], 'index.php?controller=404')) {
                            $this->logPageNotFound(self::LOG_PAGE_NOT_FOUND);
                        }
                    }
                }

                // Anti-SPAM: Block TOR network
                if (true === (bool) Configuration::get('LITE_BLOCK_TOR')) {
                    if (false === $this->context->cookie->__get('securityliteTor')) {
                        if (true === $this->isTorExitPoint(Tools::getRemoteAddr())) {
                            $this->context->cookie->__set('securityliteTor', '1'); // is TOR
                        } else {
                            $this->context->cookie->__set('securityliteTor', '0'); // is not TOR
                        }
                        $this->context->cookie->write();
                    }

                    // Block if TOR
                    if ('1' === $this->context->cookie->__get('securityliteTor')) {
                        $this->blockRequest(403);
                    }
                }

                // Ban IP addresses
                if (0 !== (int) Configuration::get('LITE_BAN_IP_ACTIVATE') && true === (bool) Configuration::get('LITE_BAN_IP')) {
                    $this->blockIp();
                }

                // Block user agents
                if (0 !== (int) Configuration::get('LITE_BLOCK_USER_AGENT_ACTIVATE') && true === (bool) Configuration::get('LITE_BLOCK_USER_AGENT')) {
                    $this->blockUserAgent();
                }
            }
        }
    }

    /**
     * Add record time to database.
     *
     * @param string $email
     * @param string $ip
     * @param string $ban
     */
    private function addRecordTime($email, $ip, $ban)
    {
        Db::getInstance()->insert('securitylite', [
            'email' => pSQL($email),
            'ip' => pSQL($ip),
            'banned' => (int) $ban,
        ]);
    }

    /**
     * Load protect content section.
     */
    private function protectContent()
    {
        // Protect content
        if (false === $this->checkWhitelist('LITE_WHITELIST_PROTECT_CONTENT')) {
            // Disable browser features
            if (1 === (int) Configuration::get('LITE_DISABLE_RIGHT_CLICK')) {
                $this->context->controller->addJS($this->_path . 'views/js/contextmenu.js');
            } elseif (2 === (int) Configuration::get('LITE_DISABLE_RIGHT_CLICK')) {
                $this->context->controller->addJS($this->_path . 'views/js/contextmenu-img.js');
            }
        }
    }

    /**
     * @param string $link
     * @param bool|null $target
     * @param bool $blank
     *
     * @return string
     */
    private function generateLink($link, $target = null, $blank = true)
    {
        if (null === $target) {
            $target = $link;
        }

        if (true === $blank) {
            return '<a href="' . $link . '" target="_blank" rel="noopener noreferrer">' . $target . '</a>';
        }

        return '<a href="' . $link . '" rel="noopener noreferrer">' . $link . '</a>';
    }

    /**
     * Return array of files that should be deleted.
     *
     * @return array
     */
    private function getFilesRoot()
    {
        // Files that should be deleted
        $files = [
            '0x666.php',
            'IndoXploit.php',
            'README.md',
            'Sh3ll.php',
            'XsamXadoo_Bot.php',
            'XsamXadoo_Bot_All.php',
            'XsamXadoo_deface.php',
            'Xsam_Xadoo.html',
            'anonsha1a0.php',
            'atx_bot.php',
            'azzoulshell.php',
            'b374k.php',
            'bajatax_xsam.php',
            'bigdump.php',
            'bypass.php',
            'c100.php',
            'c99.php',
            'cPanelCracker.php',
            'composer.json',
            'database.php',
            'docker-compose.yml',
            'docs/CHANGELOG.txt',
            'docs/readme_de.txt',
            'docs/readme_en.txt',
            'docs/readme_es.txt',
            'docs/readme_fr.txt',
            'docs/readme_it.txt',
            'efi.php',
            'f.php',
            'hacked.php',
            'httptest.php',
            'info.php',
            'kill.php',
            'lfishell.php',
            'olux.php',
            'perlinfo.php',
            'php.php',
            'phpinfo.php',
            'phppsinfo.php',
            'phpversion.php',
            'prestashop.zip',
            'proshell.php',
            'r00t.php',
            'r57.php',
            'sado.php',
            'shellwow.php',
            'simulasi.php',
            'sssp.php',
            'test.php',
            'testproxy.php',
            'upload.php',
            'wawa.php',
            'wolfm.php',
            'wso.php',
            'xGSx.php',
            'xaishell.php',
            'xcontact182.php',
            'xsam_xadoo_bot.php',
            'xsambot.php',
            'xsambot2.php',
            'xsamxadoo.php',
            'xsamxadoo101.php',
            'xsamxadoo102.php',
            'xsamxadoo95.php',
        ];

        $getFilesRoot = [];

        foreach ($files as $file) {
            $dir = _PS_ROOT_DIR_ . \DIRECTORY_SEPARATOR . $file;
            if (\file_exists($dir)) {
                $getFilesRoot[] = \realpath($dir);
            }
        }

        return $getFilesRoot;
    }

    /**
     * Get information about TLS certificate.
     *
     * @return string
     */
    private function getCertInfo()
    {
        if (false === $this->isSsl()) {
            return false;
        }

        if ('localhost' === \Tools::getHttpHost(false, true, true)) {
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

        return \openssl_x509_parse($cert['options']['ssl']['peer_certificate']);
    }

    /**
     * Generate button for links.
     *
     * @param string $text
     * @param string $url
     *
     * @return string
     */
    private function generateBtnLink($text, $url)
    {
        return '<a class="btn btn-default" href="' . $url . '" target="_blank" rel="noopener noreferrer">' . $text . '</a>';
    }

    /**
     * Generate paragraph.
     *
     * @param string $text
     * @param bool $italic
     *
     * @return string
     */
    private function addParagraph($text, $italic = false)
    {
        if (true === $italic) {
            return '<p style="font-size: 13px; font-style: italic;">' . $text . '</p>';
        }

        return '<p style="font-size: 13px;">' . $text . '</p>';
    }

    /**
     * Generate button for POST requests.
     *
     * @param string $id
     * @param bool $disabled
     * @param string $name
     *
     * @return string
     */
    private function generateBtnPost($name, $id, $disabled)
    {
        $current = $this->getAdminLink('AdminModules', true) . '&configure=securitylite';

        $script = '<script>function loading(btn){btn.disabled=true;btn.innerHTML=\'<i class="icon icon-circle-o-notch icon-spin"></i> ' . $this->l('Loading') . '...\';}</script>';

        if (true === $disabled) {
            return '<button class="btn btn-default" type="button" onclick="loading(this); window.location.href=\'' . $current . '&' . $id . '=1\'; return false;">' . $name . '</button>' . $script;
        }

        return '<button class="btn btn-default" type="button" onclick="window.location.href=\'' . $current . '&' . $id . '=1\';">' . $name . '</button>';
    }

    private function disabledBtn($name)
    {
        return '<button class="btn btn-default" type="button" disabled >' . $name . '</button>';
    }

    /**
     * @param array $array
     * @param bool $table
     *
     * @return string
     */
    private function arrayToTable($array, $table = true)
    {
        $out = [];
        $tableHeader = null;
        foreach ($array as $value) {
            if (\is_array($value)) {
                if (null === ($tableHeader)) {
                    $tableHeader =
                    '<th><strong>' . \implode('</strong></th><th><strong>', \array_keys($value)) . '</strong></th>';
                }
                \array_keys($value);
                $out[] = '<tr>' . $this->arrayToTable($value, false) . '</tr>';
            } else {
                $out[] = '<td height="30">' . $value . '</td>';
            }
        }

        if (true === $table) {
            return '<table class="table"><thead><tr>' . $tableHeader . '</tr></thead>' . \implode('', $out) . '</table>';
        }

        return \implode('', $out);
    }

    /**
     * Delete old backups from local.
     *
     * @param string $backupSaved
     * @param string $dir
     */
    private function deleteOldBackups($backupSaved, $dir)
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
    private function getBanTime($email)
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
     * Get base URL.
     *
     * @return string
     */
    private function getBaseURL()
    {
        return \Tools::getHttpHost(true, true, true) . __PS_BASE_URI__;
    }

    /**
     * Get secret TwoFactorAuth.
     *
     * @return string
     */
    private function getSecret()
    {
        if (empty($this->getTwoFactorAuthDB('secret'))) {
            Db::getInstance()->insert('securitylite_tfa', [
                'enabled' => '0',
                'secret' => '',
            ]);
            $tfa = new \RobThree\Auth\TwoFactorAuth(Configuration::get('PS_SHOP_NAME'), 6, 30, 'sha1');
            $this->updateTwoFactorAuthDB('secret', $tfa->createSecret(160, true));
        }

        return $this->getTwoFactorAuthDB('secret');
    }

    /**
     * Display reCAPTCHA and set headers.
     */
    private function displayRecaptcha()
    {
        \http_response_code(403);

        if (true === (bool) \Configuration::get('LITE_FIREWALL_RECAPTCHA_SITE_KEY')) {
            $siteKey = \Configuration::get('LITE_FIREWALL_RECAPTCHA_SITE_KEY');
        } else {
            $siteKey = '6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI';
        }
        $lang = $this->context->language->iso_code;
        \header('Connection: Close');
        \header('Cache-Control: max-age=0, private, no-store, no-cache, must-revalidate');

        echo '<!DOCTYPE html><html lang="' . $lang . '"> <head> <meta charset="utf-8"> <meta http-equiv="X-UA-Compatible" content="IE=edge"> <meta name="viewport" content="width=device-width, initial-scale=1"> <title>' . \Configuration::get('PS_SHOP_NAME') . ' ' . $this->l('is secured by') . ' ' . $this->l('Security Lite') . '</title> ' . $this->getFavicon() . ' <style>*{margin: 0; padding: 0; box-sizing: border-box; -webkit-box-sizing: border-box; -moz-box-sizing: border-box; text-rendering: optimizeLegibility; user-select: none;}body{font-family: "Roboto", Helvetica, Arial, sans-serif; font-size: 14px; line-height: 24px; color: #191919; background: #eff1f2;}.container{max-width: 450px; width: 100%; margin: 0 auto; position: relative;}#securityForm{background: #fcfcfc; padding: 25px 40px 25px 40px; margin: 120px 0; box-shadow: 0 0 20px 0 rgba(0, 0, 0, 0.2), 0 5px 5px 0 rgba(0, 0, 0, 0.24); border-radius: 2px;}#securityForm h3{display: block; font-size: 30px; font-weight: 300; margin-bottom: 10px;}.text-center{text-align: center;}.g-recaptcha{display: inline-block;}#main{width: 100%; position: relative;}#left{width: 15%; position: absolute; vertical-align: top; display: inline-block; box-sizing: border-box; -moz-box-sizing: border-box; -webkit-box-sizing: border-box;}#left img{width: 100%;}#right{padding-left: 70px; padding-top: 6px; display: inline-block; vertical-align: top; box-sizing: border-box; -moz-box-sizing: border-box; -webkit-box-sizing: border-box; font-size: 18px; line-height: 28px;}.confirm{padding-top: 8px; padding-bottom: 8px;}hr{display: block; height: 1px; border: 0; border-top: 1px solid #ccc; margin: 1.3em 0; padding: 0;}</style> <script src="https://www.google.com/recaptcha/api.js?hl=' . $lang . '" async defer></script></head> <body> <div class="container"> <form id="securityForm" method="post" name="securityForm"> <div id="main"> <div id="left"><img src="' . $this->_path . 'views/img/logo.png" alt=""></div><div id="right"><strong>' . \Configuration::get('PS_SHOP_NAME') . '</strong> <br>' . $this->l('is secured by') . ' ' . $this->l('Security Lite') . '</div></div><hr> <div class="text-center"> <p>' . $this->l('We detected unusual activity from your') . ' <strong>' . $this->l('IP') . ' ' . \Tools::getRemoteAddr() . '</strong> ' . $this->l('and has blocked access to this website') . '</p><p class="confirm"><strong>' . $this->l('Please confirm that you are not a robot') . '</strong></p><div id="target" class="g-recaptcha" data-sitekey="' . $siteKey . '" data-callback="submitForm"></div></div><input type="hidden" name="g-recaptcha-submit"> </form> </div><script>var submitForm=function(){document.securityForm.submit();}</script> </body></html>';
        exit;
    }

    /**
     * Return current admin index.
     *
     * @return string
     */
    private function currentAdminIndex()
    {
        return $this->getAdminLink('AdminModules', true) . '&configure=securitylite';
    }

    /**
     * Check CVE-2020-15162.
     *
     * @return array
     */
    private function checkCve202015162()
    {
        $check = 'CVE-2020-15162';

        if (Tools::version_compare(_PS_VERSION_, '1.7.6.8', '>=') || true === (bool) Configuration::get('LITE_DISABLE_CONTACT_FORM') || true === (bool) Configuration::get('LITE_BLOCK_FILE_UPLOAD')) {
            $status = false;
        } else {
            $status = true;
        }

        $fix = $this->l('Update PrestaShop to the latest version.');

        return [
            $check,
            $status,
            $fix,
        ];
    }

    /**
     * Check CVE-2020-15161.
     *
     * @return array
     */
    private function checkCve202015161()
    {
        $check = 'CVE-2020-15161';

        $status = false;
        if (Tools::version_compare(_PS_VERSION_, '1.7.6.8', '<')) {
            $status = true;
        }

        $fix = $this->l('Update PrestaShop to the latest version.');

        return [
            $check,
            $status,
            $fix,
        ];
    }

    /**
     * Check CVE-2020-15160.
     *
     * @return array
     */
    private function checkCve202015160()
    {
        $check = 'CVE-2020-15160';

        $status = false;
        if (Tools::version_compare(_PS_VERSION_, '1.7.6.8', '<')) {
            $status = true;
        }

        $fix = $this->l('Update PrestaShop to the latest version.');

        return [
            $check,
            $status,
            $fix,
        ];
    }

    /**
     * @return array
     */
    private function checkCve201819355()
    {
        $check = 'CVE-2018-19355';

        $status = \file_exists(_PS_MODULE_DIR_ . 'orderfiles/upload.php');

        $fix = $this->l('Update') . ' "orderfiles" ' . $this->l('module to the latest version.');

        return [
            $check,
            $status,
            $fix,
        ];
    }

    /**
     * Google reCAPTCHA check.
     */
    private function googleRecaptchaCheck()
    {
        if (null !== Tools::getValue('g-recaptcha-submit')) {
            // Validate reCAPTCHA box
            if (null !== Tools::getValue('g-recaptcha-response') && !empty(Tools::getValue('g-recaptcha-response'))) {
                // Google reCAPTCHA API secret key
                if (true === (bool) Configuration::get('LITE_FIREWALL_RECAPTCHA_SECRET')) {
                    $secretKey = Configuration::get('LITE_FIREWALL_RECAPTCHA_SECRET');
                } else {
                    $secretKey = '6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe';
                }
                // Verify the reCAPTCHA response

                $url = 'https://www.google.com/recaptcha/api/siteverify';
                $params = [
                    'secret' => $secretKey,
                    'response' => Tools::getValue('g-recaptcha-response'),
                ];

                $content = $this->getRemoteContent($url, $params);

                if (false !== $content) {
                    // Decode json data
                    $responseData = \json_decode($content, true);
                    // If reCAPTCHA response is valid
                    if ($responseData['success']) {
                        // Posted form data

                        // Unlock security vulnerability
                        $this->context->cookie->__set('securityliteRecaptcha', '1');

                        // Unlock honeypot
                        $this->context->cookie->__set('securityliteHoneypot', '0');
                        $this->context->cookie->write();
                    }
                } else {
                    return;
                }
            }
        }
    }

    /**
     * Lookup country by IP addres.
     *
     * @param string $ip
     *
     * @return string|null
     */
    private function getCountry($ip)
    {
        $url = 'https://www.iplocate.io/api/lookup/' . $ip;

        $content = $this->getCachedJsonDecodedContent($url, null, $ip, 2629746);

        if (false !== $content) {
            $country = $content['country'];
        } else {
            $country = null;
        }

        return $country;
    }

    /**
     * Log page not found.
     *
     * @param string $fileName
     */
    private function logPageNotFound($fileName)
    {
        $ip = \Tools::getRemoteAddr();

        $data = [];
        $data[] = '[' . \date('Y-m-d H:i:s') . ']';
        $data[] = '[' . $ip . ']';
        $data[] = $this->l('Error 404 at URL') . ' "' . \rawurldecode(Tools::getHttpHost(true, true, true) . $_SERVER['REQUEST_URI']) . '"';

        \file_put_contents($this->getLogFile($fileName), \implode(' ', $data) . \PHP_EOL, \FILE_APPEND);
    }

    /**
     * Log vulnerabilities.
     *
     * @param string $value
     * @param string $typeVuln
     * @param string $fileName
     */
    private function logVuln($value, $typeVuln, $fileName)
    {
        $data = [];
        $data[] = '[' . \date('Y-m-d H:i:s') . ']';
        $data[] = '[' . \Tools::getRemoteAddr() . ']';
        if (null !== $typeVuln) {
            $data[] = '[' . $typeVuln . ']';
        }
        if (null !== $value) {
            $value = \str_replace(["\r", "\n"], '', $value);
            $data[] = $this->l('request') . ' "' . ($value) . '",';
        }
        $data[] = $this->l('URL') . ' "' . \rawurldecode(Tools::getHttpHost(true, true, true) . $_SERVER['REQUEST_URI']) . '"';

        \file_put_contents($this->getLogFile($fileName), \implode(' ', $data) . \PHP_EOL, \FILE_APPEND);
    }

    /**
     * Vuln detected HTML.
     *
     * @param string|null $value
     * @param string $typeVuln
     * @param int $conf
     *
     * @return bool|string
     */
    private function vulnDetectedHtml($value, $typeVuln, $conf)
    {
        // PrestaShop core whitelist
        if ($this->isInWhitelistForGeolocation(\Tools::getRemoteAddr())) {
            return false;
        }

        if (true === (bool) Configuration::get('LITE_FIREWALL_LOG')) {
            $this->logVuln(
                $value,
                $typeVuln,
                self::LOG_FIREWALL
            );
        }

        switch ($conf) {
            case 0:
                return;
            case 1:
                return $this->blockRequest(403);
            case 2:
                return \Tools::redirect('pagenotfound');
            case 3:
                return $this->displayRecaptcha();

            default:
                return;
        }
    }

    /**
     * Get two-factor authentication database value.
     *
     * @param string $column
     *
     * @return array
     */
    private function getTwoFactorAuthDB($column)
    {
        $sql = new DbQuery();
        $sql->from('securitylite_tfa');
        $sql->select($column);

        return Db::getInstance()->getValue($sql);
    }

    /**
     * Update two-factor authentication in database.
     *
     * @param string $column
     * @param int $value
     *
     * @return array
     */
    private function updateTwoFactorAuthDB($column, $value)
    {
        $query = 'UPDATE `' . _DB_PREFIX_ . 'securitylite_tfa` SET ' . pSQL($column) . '="' . pSQL($value) . '"';

        return Db::getInstance()->Execute($query);
    }

    /**
     * @param string $userIp
     *
     * @return bool|null
     */
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

    /**
     * Validate IP addresses.
     *
     * @param string $field
     */
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

        $ips = \explode(',', $input);
        $output = [];
        foreach ($ips as &$ip) {
            if (!empty(\IPLib\Factory::rangeFromString($ip))) {
                if ('LITE_BAN_IP' === $field) {
                    if (false === $this->isInWhitelistForGeolocation($ip)) {
                        $output[] = $ip;
                    }
                } else {
                    $output[] = $ip;
                }
            }
        }

        Configuration::updateValue($field, \implode(',', $output));
    }

    /**
     * Validate comma separated string.
     *
     * @param string $field
     */
    private function validateCommaSeparatedString($field)
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

    /**
     * Check CVE-2019-13461.
     *
     * @return array
     */
    private function checkCve201913461()
    {
        $check = 'CVE-2019-13461';
        $status = Tools::version_compare(_PS_VERSION_, '1.7.6.0', '<=');
        $fix = $this->l('Update PrestaShop to the latest version.');

        return [
            $check,
            $status,
            $fix,
        ];
    }

    /**
     * Check CVE-2019-11876.
     *
     * @return array
     */
    private function checkCve201911876()
    {
        $check = 'CVE-2019-11876';

        $path = \realpath(_PS_ROOT_DIR_ . \DIRECTORY_SEPARATOR . 'install');
        $status = \is_dir($path);
        $fix = $this->l('Delete folder') . ': ' . $path;

        return [
            $check,
            $status,
            $fix,
        ];
    }

    /**
     * Check CVE-2018-19124.
     *
     * @return array
     */
    private function checkCve201819124()
    {
        $check = 'CVE-2018-19124';

        $status = false;

        if ((Tools::version_compare((float) _PS_VERSION_, '1.6', '==') && Tools::version_compare(_PS_VERSION_, '1.6.1.23', '<')) || (Tools::version_compare((float) _PS_VERSION_, '1.7', '==') && Tools::version_compare(_PS_VERSION_, '1.7.4.4', '<'))) {
            if (\extension_loaded('phar') && !\ini_get('phar.readonly')) {
                $status = true;
            }
        }

        $fix = $this->l('Set') . ' "phar.readonly = 0" ' . $this->l('in your php.ini file.');

        return [
            $check,
            $status,
            $fix,
        ];
    }

    /**
     * Check CVE-2018-19125.
     *
     * @return array
     */
    private function checkCve201819125()
    {
        $check = 'CVE-2018-19125';

        $status = false;

        if ((Tools::version_compare((float) _PS_VERSION_, '1.6', '==') && Tools::version_compare(_PS_VERSION_, '1.6.1.23', '<')) || (Tools::version_compare((float) _PS_VERSION_, '1.7', '==') && Tools::version_compare(_PS_VERSION_, '1.7.4.4', '<'))) {
            if (\extension_loaded('phar') && !\ini_get('phar.readonly')) {
                $status = true;
            }
        }

        $fix = $this->l('Set') . ' "phar.readonly = 0" ' . $this->l('in your php.ini file.');

        return [
            $check,
            $status,
            $fix,
        ];
    }

    /**
     * Check CVE-2018-19126.
     *
     * @return array
     */
    private function checkCve201819126()
    {
        $check = 'CVE-2018-19126';

        $status = false;

        if ((Tools::version_compare((float) _PS_VERSION_, '1.6', '==') && Tools::version_compare(_PS_VERSION_, '1.6.1.23', '<')) || (Tools::version_compare((float) _PS_VERSION_, '1.7', '==') && Tools::version_compare(_PS_VERSION_, '1.7.4.4', '<'))) {
            if (\extension_loaded('phar') && !\ini_get('phar.readonly')) {
                $status = true;
            }
        }

        $fix = $this->l('Set') . ' "phar.readonly = 0" ' . $this->l('in your php.ini file.');

        return [
            $check,
            $status,
            $fix,
        ];
    }

    /**
     * Check CVE-2018-13784.
     *
     * @return array
     */
    private function checkCve201813784()
    {
        $check = 'CVE-2018-13784';

        $status = false;

        if ((Tools::version_compare((float) _PS_VERSION_, '1.6', '==') && Tools::version_compare(_PS_VERSION_, '1.6.1.20', '<')) || (Tools::version_compare((float) _PS_VERSION_, '1.7', '==') && Tools::version_compare(_PS_VERSION_, '1.7.3.4', '<'))) {
            $status = true;
        }
        $fix = $this->l('Update PrestaShop to the latest version.');

        return [
            $check,
            $status,
            $fix,
        ];
    }

    /**
     * Check CVE-2018-8823.
     *
     * @return array
     */
    private function checkCve20188823()
    {
        $check = 'CVE-2018-8823';
        $status = false;

        if (\file_exists(_PS_MODULE_DIR_ . 'bamegamenu/ajax_phpcode.php')) {
            $moduleVersion = Module::getInstanceByName('bamegamenu')->version;
            if (!empty($moduleVersion)) {
                if (Tools::version_compare($moduleVersion, '1.0.32', '<=')) {
                    $status = true;
                }
            }
        }
        $fix = $this->l('Update module') . '\' Responsive Mega Menu (Horizontal+Vertical+Dropdown) Pro\'';

        return [
            $check,
            $status,
            $fix,
        ];
    }

    /**
     * Check CVE-2018-8824.
     *
     * @return array
     */
    private function checkCve20188824()
    {
        $check = 'CVE-2018-8824';
        $status = false;

        if (\file_exists(_PS_MODULE_DIR_ . 'bamegamenu/ajax_phpcode.php')) {
            $moduleVersion = Module::getInstanceByName('bamegamenu')->version;
            if (!empty($moduleVersion)) {
                if (Tools::version_compare($moduleVersion, '1.0.32', '<=')) {
                    $status = true;
                }
            }
        }
        $fix = $this->l('Update module') . '\' Responsive Mega Menu (Horizontal+Vertical+Dropdown) Pro\'';

        return [
            $check,
            $status,
            $fix,
        ];
    }

    /**
     * Check CVE-2018-7491.
     *
     * @return array
     */
    private function checkCve20187491()
    {
        $check = 'CVE-2018-7491';

        if (Language::countActiveLanguages() > 1) {
            $url = $this->getBaseURL() . '/' . $this->context->language->iso_code . '/';
        } else {
            $url = $this->getBaseURL();
        }

        $headers = @\get_headers($url, 1);

        $status = true;

        if ('sameorigin' === \is_array(Tools::strtolower(isset($headers['X-Frame-Options']) ? $headers['X-Frame-Options'] : '')) ||
            'sameorigin' === Tools::strtolower(isset($headers['X-Frame-Options']) ? $headers['X-Frame-Options'] : '') ||
            Configuration::get('LITE_CLICK_JACKING')) {
            $status = false;
        }

        $fix = $this->l('Enable') . ' ' . $this->l('Click-jack protection') . ' ' . $this->l('in') . ' \'' . $this->l('HTTP Security Headers') . '\'.';

        return [
            $check,
            $status,
            $fix,
        ];
    }

    /**
     * Check CVE-2017-9841.
     *
     * @return array
     */
    private function checkCve20179841()
    {
        $check = 'CVE-2017-9841';

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
     * Check if PrestaShop version is up to date.
     *
     * @return array
     */
    private function checkPrestaShopVersion()
    {
        // Add Version tab
        if (\defined('_TB_VERSION_')) {
            $cmsName = 'Thirty bees';
            $cmsVersion = _TB_VERSION_;
            $status = false;
        } else {
            $cmsName = 'PrestaShop';
            $cmsVersion = _PS_VERSION_;
            $status = $this->checkPrestaShopUpToDate();
        }

        $check = $cmsName . ' ' . $this->l('version') . ' (' . $cmsVersion . ')';

        $fix = $this->l('Update PrestaShop to the latest version.');

        $desc = $this->l('It is strongly recommended to upgrade the store to the latest version of PrestaShop as new versions include bug fixes and security fixes.');

        return [
            $check,
            $status,
            $fix,
            $desc,
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

        if (Tools::version_compare(_PS_VERSION_, '1.7.5.0', '<')) {
            $status = Tools::version_compare(Tools::checkPhpVersion(), $this->getNewestPhpVersion('7.1'), '<');
            $fix = $this->l('Update the PHP version to') . ' ' . $this->getNewestPhpVersion('7.1') . '.';
        } elseif (Tools::version_compare(_PS_VERSION_, '1.7.7.0', '<')) {
            $status = Tools::version_compare(Tools::checkPhpVersion(), $this->getNewestPhpVersion('7.2'), '<');
            $fix = $this->l('Update the PHP version to') . ' ' . $this->getNewestPhpVersion('7.2') . '.';
        } elseif (Tools::version_compare(_PS_VERSION_, '1.7.7.0', '>=')) {
            $status = Tools::version_compare(Tools::checkPhpVersion(), $this->getNewestPhpVersion('7.3'), '<');
            $fix = $this->l('Update the PHP version to') . ' ' . $this->getNewestPhpVersion('7.3') . '.';
        } else {
            $status = Tools::version_compare(Tools::checkPhpVersion(), $this->getNewestPhpVersion('7.4'), '<');
            $fix = $this->l('Update the PHP version to') . ' ' . $this->getNewestPhpVersion('7.4') . '.';
        }

        $desc = $this->l('The most obvious reason to update PHP is security. Newer versions are better at countering hackers, but the performance is also better in the newer PHP versions.');

        return [
            $check,
            $status,
            $fix,
            $desc,
        ];
    }

    /**
     * Check if PrestaShop TLS is enabled.
     *
     * @return array
     */
    private function checkTlsEnabled()
    {
        $check = $this->l('SSL enabled');

        $status = false === (bool) Configuration::get('PS_SSL_ENABLED');

        $fix = $this->l('Enable SSL in') . ' ' . $this->generateLink($this->getAdminLink('AdminPreferences', true), $this->l('\'Shop Parameters\' > \'General\''));

        $desc = $this->l('If you own an SSL certificate for your shop\'s domain name, you can activate SSL encryption (https://) for customer account identification and order processing.');

        return [
            $check,
            $status,
            $fix,
            $desc,
        ];
    }

    /**
     * Check if PrestaShop TLS everywhere is enabled.
     *
     * @return array
     */
    private function checkTlsEnabledEverywhere()
    {
        $check = $this->l('SSL enabled everywhere');

        $status = false === (bool) Configuration::get('PS_SSL_ENABLED_EVERYWHERE');

        $fix = $this->l('Enable SSL everywhere in') . ' ' . $this->generateLink($this->getAdminLink('AdminPreferences', true), $this->l('\'Shop Parameters\' > \'General\''));

        $desc = $this->l('When enabled, all the pages of your shop will be SSL-secured.');

        return [
            $check,
            $status,
            $fix,
            $desc,
        ];
    }

    /**
     * Check if PrestaShop token is activated.
     *
     * @return array
     */
    private function checkPrestashopToken()
    {
        $check = $this->l('Security token');

        $status = false === (bool) Configuration::get('PS_TOKEN_ENABLE');

        $fix = $this->l('Enable Increase front office security in') . ' ' . $this->generateLink($this->getAdminLink('AdminPreferences', true), $this->l('\'Shop Parameters\' > \'General\''));

        $desc = $this->l('Enable token in the front office to improve PrestaShop\'s security.');

        return [
            $check,
            $status,
            $fix,
            $desc,
        ];
    }

    /**
     * Check if Mod Secure is active.
     *
     * @return array
     */
    private function checkModSecurity()
    {
        $check = 'ModSecurity';

        $status = (bool) Configuration::get('PS_HTACCESS_DISABLE_MODSEC');

        $fix = $this->l('Enable Apache\'s \'mod_security\' module in') . ' ' . $this->generateLink($this->getAdminLink('AdminMeta', true), $this->l('\'Shop Parameters\' > \'Traffic and SEO\''));

        $desc = $this->l('Enable Apache\'s mod_security module to harden the security of your shop.');

        return [
            $check,
            $status,
            $fix,
            $desc,
        ];
    }

    /**
     * Check if PrestaShop admin directory name is secure.
     *
     * @return array
     */
    private function checkAdminDirectoryName()
    {
        $check = $this->l('Admin folder name');

        $status = !\preg_match('/[A-Za-z].*[0-9]|[0-9].*[A-Za-z]/', \basename(_PS_ADMIN_DIR_));

        $fix = $this->l('Use both letters and numbers in the name of your admin folder.');

        $desc = $this->l('To make it harder for attackers to guess the URL, use both letters and numbers in the name of your admin folder.');

        return [
            $check,
            $status,
            $fix,
            $desc,
        ];
    }

    /**
     * Check if PrestaShop develop mode is active.
     *
     * @return array
     */
    private function checkPrestashopDevMode()
    {
        $check = $this->l('Debug mode');

        $status = _PS_MODE_DEV_;

        $fix = $this->l('Disabling the debug mode at') . ' ' . $this->generateLink($this->getAdminLink('AdminPerformance', true), $this->l('\'Advanced Parameters\' > \'Performance\''));

        $desc = $this->l('Once your shop is in production, you must disable the debug mode. It can leak pieces of information that a hacker can use.');

        return [
            $check,
            $status,
            $fix,
            $desc,
        ];
    }

    /**
     * Check the cookie's IP address.
     *
     * @return array
     */
    private function checkCookieIpAddress()
    {
        $check = $this->l('Cookie\'s IP address');

        $status = false === (bool) Configuration::get('PS_COOKIE_CHECKIP');

        $fix = $this->l('Enable check of cookie IP address at') . ' ' . $this->generateLink($this->getAdminLink('AdminAdminPreferences', true), $this->l('\'Advanced Parameters\' > \'Administration\''));

        $desc = $this->l('Check the IP address of the cookie to prevent your cookie from being stolen.');

        return [
            $check,
            $status,
            $fix,
            $desc,
        ];
    }

    /**
     * Check CVE-2020-15083.
     *
     * @return array
     */
    private function checkCve202015083()
    {
        $check = 'CVE-2020-15083';
        $status = false;
        if (Tools::version_compare(_PS_VERSION_, '1.7.0.0', '>=') && Tools::version_compare(_PS_VERSION_, '1.7.6.6', '<')) {
            $status = true;
        }

        $fix = $this->l('Update PrestaShop to the latest version.');

        return [
            $check,
            $status,
            $fix,
        ];
    }

    /**
     * Check CVE-2020-15079.
     *
     * @return array
     */
    private function checkCve202015079()
    {
        $check = 'CVE-2020-15079';
        $status = false;
        if (Tools::version_compare(_PS_VERSION_, '1.7.6.6', '<')) {
            $status = true;
        }

        $fix = $this->l('Update PrestaShop to the latest version.');

        return [
            $check,
            $status,
            $fix,
        ];
    }

    /**
     * Check CVE-2020-4074.
     *
     * @return array
     */
    private function checkCve20204074()
    {
        $check = 'CVE-2020-4074';
        $status = false;
        if (Tools::version_compare(_PS_VERSION_, '1.7.6.6', '<')) {
            $status = true;
        }

        $fix = $this->l('Update PrestaShop to the latest version.');

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
    private function checkCve20205250()
    {
        $check = 'CVE-2020-5250';
        $status = false;
        if (Tools::version_compare(_PS_VERSION_, '1.7.0.0', '>=') && Tools::version_compare(_PS_VERSION_, '1.7.6.4', '<')) {
            $status = true;
        }

        $fix = $this->l('Update PrestaShop to the latest version.');

        return [
            $check,
            $status,
            $fix,
        ];
    }

    /**
     * Check CVE-2020-5264.
     *
     * @return array
     */
    private function checkCve20205264()
    {
        $check = 'CVE-2020-5264';

        $status = false;
        if (Tools::version_compare(_PS_VERSION_, '1.7.0.0', '>=') && Tools::version_compare(_PS_VERSION_, '1.7.6.5', '<')) {
            $status = true;
        }

        $fix = $this->l('Update PrestaShop to the latest version.');

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
        $check = 'CVE-2020-5265';

        $status = false;
        if (Tools::version_compare(_PS_VERSION_, '1.7.6.1', '>=') && Tools::version_compare(_PS_VERSION_, '1.7.6.5', '<')) {
            $status = true;
        }

        $fix = $this->l('Update PrestaShop to the latest version.');

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
        $check = 'CVE-2020-5269';

        $status = false;
        if (Tools::version_compare(_PS_VERSION_, '1.7.6.1', '>=') && Tools::version_compare(_PS_VERSION_, '1.7.6.5', '<')) {
            $status = true;
        }

        $fix = $this->l('Update PrestaShop to the latest version.');

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
        $check = 'CVE-2020-5270';

        $status = false;
        if (Tools::version_compare(_PS_VERSION_, '1.7.6.0', '>=') && Tools::version_compare(_PS_VERSION_, '1.7.6.5', '<')) {
            $status = true;
        }

        $fix = $this->l('Update PrestaShop to the latest version.');

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
        $check = 'CVE-2020-5272';

        $status = false;
        if (Tools::version_compare(_PS_VERSION_, '1.5.5.0', '>=') && Tools::version_compare(_PS_VERSION_, '1.7.6.5', '<')) {
            $status = true;
        }

        $fix = $this->l('Update PrestaShop to the latest version.');

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
        $check = 'CVE-2020-5279';

        $status = false;
        if (Tools::version_compare(_PS_VERSION_, '1.5.0.0', '>=') && Tools::version_compare(_PS_VERSION_, '1.7.6.5', '<')) {
            $status = true;
        }

        $fix = $this->l('Update PrestaShop to the latest version.');

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
        $check = 'CVE-2020-5276';

        $status = false;
        if (Tools::version_compare(_PS_VERSION_, '1.7.1.0', '>=') && Tools::version_compare(_PS_VERSION_, '1.7.6.5', '<')) {
            $status = true;
        }

        $fix = $this->l('Update PrestaShop to the latest version.');

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
        $check = 'CVE-2020-5278';

        $status = false;
        if (Tools::version_compare(_PS_VERSION_, '1.5.4.0', '>=') && Tools::version_compare(_PS_VERSION_, '1.7.6.5', '<')) {
            $status = true;
        }

        $fix = $this->l('Update PrestaShop to the latest version.');

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
        $check = 'CVE-2020-5286';

        $status = false;
        if (Tools::version_compare(_PS_VERSION_, '1.7.4.0', '>=') && Tools::version_compare(_PS_VERSION_, '1.7.6.5', '<')) {
            $status = true;
        }

        $fix = $this->l('Update PrestaShop to the latest version.');

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
        $check = 'CVE-2020-5285';

        $status = false;
        if (Tools::version_compare(_PS_VERSION_, '1.7.6.0', '>=') && Tools::version_compare(_PS_VERSION_, '1.7.6.5', '<')) {
            $status = true;
        }

        $fix = $this->l('Update PrestaShop to the latest version.');

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
        $check = 'CVE-2020-5287';

        $status = false;
        if (Tools::version_compare(_PS_VERSION_, '1.5.5.0', '>=') && Tools::version_compare(_PS_VERSION_, '1.7.6.5', '<')) {
            $status = true;
        }

        $fix = $this->l('Update PrestaShop to the latest version.');

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
        $check = 'CVE-2020-5288';

        $status = false;
        if (Tools::version_compare(_PS_VERSION_, '1.7.0.0', '>=') && Tools::version_compare(_PS_VERSION_, '1.7.6.5', '<')) {
            $status = true;
        }

        $fix = $this->l('Update PrestaShop to the latest version.');

        return [
            $check,
            $status,
            $fix,
        ];
    }

    /**
     * Check CVE-2020-15080.
     *
     * @return array
     */
    private function checkCve202015080()
    {
        $check = 'CVE-2020-15080';

        $files = [
            'composer.json',
            'docker-compose.yml',
        ];

        $root = _PS_CORE_DIR_ . \DIRECTORY_SEPARATOR;
        $result = [];
        foreach ($files as $file) {
            if (\file_exists($root . $file)) {
                $result[] = $root . $file;
            }
        }

        if (!empty($result)) {
            $status = true;
        } else {
            $status = false;
        }

        $fix = $this->l('Delete following files') . ':<br>' . \implode('<br>', $result);

        return [
            $check,
            $status,
            $fix,
        ];
    }

    /**
     * Check CVE-2020-15081.
     *
     * @return array
     */
    private function checkCve202015081()
    {
        $check = 'CVE-2020-15081';

        $status = false;
        if (Tools::version_compare(_PS_VERSION_, '1.7.6.6', '<')) {
            $status = true;
        }

        $fix = $this->l('Update PrestaShop to the latest version.');

        return [
            $check,
            $status,
            $fix,
        ];
    }

    /**
     * Check CVE-2020-15082.
     *
     * @return array
     */
    private function checkCve202015082()
    {
        $check = 'CVE-2020-15082';

        $status = false;
        if (Tools::version_compare(_PS_VERSION_, '1.7.6.6', '<')) {
            $status = true;
        }

        $fix = $this->l('Update PrestaShop to the latest version.');

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
        $check = 'CVE-2020-5293';

        $status = false;
        if (Tools::version_compare(_PS_VERSION_, '1.7.0.0', '>=') && Tools::version_compare(_PS_VERSION_, '1.7.6.5', '<')) {
            $status = true;
        }

        $fix = $this->l('Update PrestaShop to the latest version.');

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
        $check = 'CVE-2020-5271';

        $status = false;
        if (Tools::version_compare(_PS_VERSION_, '1.6.0.0', '>=') && Tools::version_compare(_PS_VERSION_, '1.7.6.5', '<')) {
            $status = true;
        }

        $fix = $this->l('Update PrestaShop to the latest version.');

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
    private function checkSessionAutoStart()
    {
        $key = 'session.auto_start';
        if (false !== $this->isOn(\ini_get($key))) {
            $current = $this->isOn(\ini_get($key));
        } else {
            $current = '0';
        }

        $recommended = '0';

        if ($current === $recommended) {
            $status = false;
        } else {
            $status = true;
        }
        $desc = $this->l('It is considered to bad practice to autostart sessions.');

        return [
            $key,
            $current,
            $recommended,
            $status,
            $desc,
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

        $recommended = '1';

        if ($current === $recommended) {
            $status = false;
        } else {
            $status = true;
        }
        $desc = $this->l('Accepts cookies to manage sessions.');

        return [
            $key,
            $current,
            $recommended,
            $status,
            $desc,
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

        $recommended = '1';

        if ($current === $recommended) {
            $status = false;
        } else {
            $status = true;
        }
        $desc = $this->l('Must use cookies to manage sessions, don\'t accept session-ids in a link.');

        return [
            $key,
            $current,
            $recommended,
            $status,
            $desc,
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

        $recommended = '1';

        if ($current === $recommended) {
            $status = false;
        } else {
            $status = true;
        }

        $desc = $this->l('Setting session cookies to \'HTTP only\' makes them only readable by the browser.');

        return [
            $key,
            $current,
            $recommended,
            $status,
            $desc,
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
        $recommended = '0';
        if ($current === $recommended) {
            $status = false;
        } else {
            $status = true;
        }

        $desc = $this->l('If used') . ' \'use_trans_sid\' ' . $this->l('setting puts the session ID on the URL, making it easier to hijack.');

        return [
            $key,
            $current,
            $recommended,
            $status,
            $desc,
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

        if (true === $this->isSsl()) {
            $recommended = '1';
        } else {
            $recommended = '0';
        }

        if ($current === $recommended) {
            $status = false;
        } else {
            $status = true;
        }

        $desc = $this->l('Cookie secure specifies whether cookies should only be sent over secure connections.') . ' ' . $this->l('This setting requires SSL/TLS to be enabled.');

        return [
            $key,
            $current,
            $recommended,
            $status,
            $desc,
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
        $recommended = '0';
        if ($current === $recommended) {
            $status = false;
        } else {
            $status = true;
        }

        $desc = $this->l('It tells browsers not to store the session cookie to permanent storage. Therefore, when the browser is terminated, the session ID cookie is deleted immediately.');

        return [
            $key,
            $current,
            $recommended,
            $status,
            $desc,
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
        $recommended = '1';
        if ($current === $recommended) {
            $status = false;
        } else {
            $status = true;
        }

        $desc = $this->l('Strict mode prevents uninitialized session ID\'s in the built-in session handling.');

        return [
            $key,
            $current,
            $recommended,
            $status,
            $desc,
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

        if (Tools::version_compare(Tools::checkPhpVersion(), '7.0.0', '>=')) {
            if (false !== $this->isOn(\ini_get($key))) {
                $current = $this->isOn(\ini_get($key));
            } else {
                $current = '0';
            }
            $recommended = '1';
            $desc = $this->l('Lazy session writes only when the session data has been modified. This should be enabled to prevent potential information exposure.');
        } else {
            $current = false;
            $recommended = false;
            $desc = $this->l('The INI setting') . ' \'' . $key . '\' ' . $this->l('was added in') . ' PHP 7.0.0.';
        }

        if ($current === $recommended) {
            $status = false;
        } else {
            $status = true;
        }

        return [
            $key,
            $current,
            $recommended,
            $status,
            $desc,
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

        if (Tools::version_compare(Tools::checkPhpVersion(), '7.1.0', '>=')) {
            if (false !== \ini_get($key)) {
                $current = \ini_get($key);
            } else {
                $current = '32';
            }
            $recommended = '128';
            $desc = $this->l('Increasing the session ID length will make it harder for an attacker to guess it (via brute force or more likely side-channel attacks).');
            if ((int) $current >= (int) $recommended) {
                $status = false;
            } else {
                $status = true;
            }
        } else {
            $current = false;
            $recommended = false;
            $status = false;
            $desc = $this->l('The INI setting') . ' \'' . $key . '\' ' . $this->l('was added in') . ' PHP 7.1.0.';
        }

        return [
            $key,
            $current,
            $recommended,
            $status,
            $desc,
        ];
    }

    /**
     * Check php.ini conf: session.gc_probability.
     *
     * @return array
     */
    private function checkSessionGcProbability()
    {
        $key = 'session.gc_probability';
        if (false !== $this->isOn(\ini_get($key))) {
            $current = $this->isOn(\ini_get($key));
        } else {
            $current = '1';
        }
        $recommended = '1';
        if ($current === $recommended) {
            $status = false;
        } else {
            $status = true;
        }

        $desc = $this->l('Defines the probability that the \'garbage collection\' process is started on every session initialization.');

        return [
            $key,
            $current,
            $recommended,
            $status,
            $desc,
        ];
    }

    /**
     * Check php.ini conf: session.gc_divisor.
     *
     * @return array
     */
    private function checkSessionGcDivisor()
    {
        $key = 'session.gc_divisor';
        if (false !== \ini_get($key)) {
            $current = \ini_get($key);
        } else {
            $current = '100';
        }
        $recommended = '1000';
        if ($current === $recommended) {
            $status = false;
        } else {
            $status = true;
        }

        $desc = $this->l('Defines the probability that the \'garbage collection\' process is started on every session initialization.');

        return [
            $key,
            $current,
            $recommended,
            $status,
            $desc,
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

        if (Tools::version_compare(Tools::checkPhpVersion(), '7.1.0', '>=')) {
            if (false !== \ini_get($key)) {
                $current = \ini_get($key);
            } else {
                $current = '4';
            }
            $recommended = '6';
            $desc = $this->l('The more bits result in stronger session ID.');
            if ((int) $current >= (int) $recommended) {
                $status = false;
            } else {
                $status = true;
            }
        } else {
            $current = false;
            $recommended = false;
            $status = false;
            $desc = $this->l('The INI setting') . ' \'' . $key . '\' ' . $this->l('was added in') . ' PHP 7.1.0.';
        }

        return [
            $key,
            $current,
            $recommended,
            $status,
            $desc,
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
        $recommended = '1';
        if ($current === $recommended) {
            $status = false;
        } else {
            $status = true;
        }

        $desc = $this->l('This directive enables PrestaShop to access remote files, which is an essential part of the payment process, among other things. it\'s therefore imperative to have it enabled.');

        return [
            $key,
            $current,
            $recommended,
            $status,
            $desc,
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
        $recommended = '0';
        if ($current === $recommended) {
            $status = false;
        } else {
            $status = true;
        }

        $desc = $this->l('don\'t allow the inclusion of remote file resources.');

        return [
            $key,
            $current,
            $recommended,
            $status,
            $desc,
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
        $recommended = '0';
        if ($current === $recommended) {
            $status = false;
        } else {
            $status = true;
        }

        $desc = $this->l('Don\'t show errors in production.');

        return [
            $key,
            $current,
            $recommended,
            $status,
            $desc,
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
        $recommended = '1';
        if ($current === $recommended) {
            $status = false;
        } else {
            $status = true;
        }

        $desc = $this->l('Log errors in production.');

        return [
            $key,
            $current,
            $recommended,
            $status,
            $desc,
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
        $recommended = '0';
        if ($current === $recommended) {
            $status = false;
        } else {
            $status = true;
        }

        $desc = $this->l('Showing the PHP signature exposes additional information.');

        return [
            $key,
            $current,
            $recommended,
            $status,
            $desc,
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
        $recommended = '0';
        if ($current === $recommended) {
            $status = false;
        } else {
            $status = true;
        }

        $desc = $this->l('Whether to declare the argv & argc variables (that would contain the GET information).');

        return [
            $key,
            $current,
            $recommended,
            $status,
            $desc,
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

        $recommended = '0';
        if ($current === $recommended) {
            $status = false;
        } else {
            $status = true;
        }

        $desc = $this->l('Not a direct security vulnerability but it could become one given the proper conditions.');

        return [
            $key,
            $current,
            $recommended,
            $status,
            $desc,
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
        $recommended = '22M';
        if ($this->convertToBytes($current) <= $this->convertToBytes($recommended)) {
            $status = false;
        } else {
            $status = true;
        }

        $desc = $this->l('Unless necessary, a maximum post size of') . ' ' . $current . ' ' . $this->l('is too large.');

        return [
            $key,
            $current,
            $recommended,
            $status,
            $desc,
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
        $recommended = '20000';
        if ((int) $current <= (int) $recommended) {
            $status = false;
        } else {
            $status = true;
        }

        $desc = $this->l('A maximum number of input variables should be defined to prevent performance issues.');

        return [
            $key,
            $current,
            $recommended,
            $status,
            $desc,
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
        $recommended = '300';
        if ((int) $current <= (int) $recommended && '-1' !== $current && 0 !== (int) $current) {
            $status = false;
        } else {
            $status = true;
        }

        $desc = $this->l('Maximum amount of time each script may spend parsing request data. It\'s a good idea to limit this time on productions servers to eliminate unexpectedly long-running scripts.');

        return [
            $key,
            $current,
            $recommended,
            $status,
            $desc,
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
        $recommended = '0';
        if ($current === $recommended) {
            $status = false;
        } else {
            $status = true;
        }

        $desc = $this->l('Showing startup errors could provide extra information to potential attackers.');

        return [
            $key,
            $current,
            $recommended,
            $status,
            $desc,
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
        $recommended = '0';
        if ($current === $recommended) {
            $status = false;
        } else {
            $status = true;
        }

        $desc = $this->l('Error reporting should be different based on context.');

        return [
            $key,
            $current,
            $recommended,
            $status,
            $desc,
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
        $recommended = '20M';

        if ($this->convertToBytes($current) <= $this->convertToBytes($recommended)) {
            $status = false;
        } else {
            $status = true;
        }

        $desc = $this->l('A maximum upload size should be defined to prevent server overload from large requests.');

        return [
            $key,
            $current,
            $recommended,
            $status,
            $desc,
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
        $recommended = '512M';
        if ($this->convertToBytes($current) <= $this->convertToBytes($recommended) && '-1' !== $current) {
            $status = false;
        } else {
            $status = true;
        }

        $desc = $this->l('The standard memory limit should not be too high, if you need more memory for a single script you can adjust that during runtime using') . ' ini_set().';

        return [
            $key,
            $current,
            $recommended,
            $status,
            $desc,
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
        $recommended = 'utf-8';
        if (Tools::strtolower($current) === $recommended) {
            $status = false;
        } else {
            $status = true;
        }

        $desc = $this->l('Ensure that a default character set is defined, utf-8 is preferred.');

        return [
            $key,
            $current,
            $recommended,
            $status,
            $desc,
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
        $recommended = '300';
        if ($current <= $recommended) {
            $status = false;
        } else {
            $status = true;
        }

        $desc = $this->l('To prevent denial-of-service attacks where an attacker tries to keep your server\'s CPU busy, this value should be set to the lowest possible value.');

        return [
            $key,
            $current,
            $recommended,
            $status,
            $desc,
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
        $recommended = '1';
        if ($current === $recommended) {
            $status = false;
        } else {
            $status = true;
        }

        $desc = $this->l('PrestaShop require HTTP file uploads.');

        return [
            $key,
            $current,
            $recommended,
            $status,
            $desc,
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
     * Reset in case of error.
     */
    private function onErrorHtpasswd()
    {
        Configuration::updateValue('LITE_HTPASSWD', false);

        $this->removeHtaccessContent();
    }

    /**
     * Add missing index.php files.
     *
     * @param string $path
     * @param bool $analyze
     */
    private function addIndexRecursively($path, $analyze = false)
    {
        if (0 === \mb_strpos(\basename($path), '.')) {
            return;
        }

        $indexFilePath = $path . \DIRECTORY_SEPARATOR . 'index.php';

        if (false === \file_exists($indexFilePath)) {
            if (true === $analyze) {
                $reportPath = _PS_MODULE_DIR_;
                if (!\is_dir($reportPath)) {
                    \mkdir($reportPath, 0755, true);
                }
                \file_put_contents($reportPath . \DIRECTORY_SEPARATOR . self::REPORT_CREATE_INDEX, \realpath($path) . \PHP_EOL, \FILE_APPEND | \LOCK_EX);
            } else {
                \file_put_contents($indexFilePath, Tools::getDefaultIndexContent());
            }
        }

        $dirs = \glob($path . \DIRECTORY_SEPARATOR . '*', \GLOB_ONLYDIR);

        if (false === $dirs) {
            return;
        }

        foreach ($dirs as $dir) {
            if (true === $analyze) {
                $this->addIndexRecursively($dir, true);
            } else {
                $this->addIndexRecursively($dir);
            }
        }
    }

    private function getHtaccessContent()
    {
        return '# Apache 2.2
<IfModule !mod_authz_core.c>
    Order deny,allow
    Deny from all
</IfModule>

# Apache 2.4
<IfModule mod_authz_core.c>
    Require all denied
</IfModule>
';
    }

    /**
     * Analyze file- and directory permissions.
     *
     * @param string $dir
     */
    private function chmodFileFolderAnalyze($dir)
    {
        $perms = [];
        $perms['file'] = 0644;
        $perms['folder'] = 0755;
        $dh = @\opendir($dir);

        $reportPath = _PS_MODULE_DIR_ . self::REPORT_PERMISSIONS;

        if ($dh) {
            $myfile = \fopen($reportPath, 'ab');
            while (false !== ($file = \readdir($dh))) {
                if ('.' !== $file && '..' !== $file) {
                    $fullpath = $dir . '/' . $file;
                    if (!\is_dir($fullpath)) {
                        if (Tools::substr(\sprintf('%o', \fileperms($fullpath)), -3) !== \decoct($perms['file'])) {
                            \fwrite($myfile, $this->l('Permission') . ' ' . Tools::substr(\decoct(\fileperms($fullpath)), -3) . ': ' . $fullpath . \PHP_EOL);
                        }
                    } else {
                        if (Tools::substr(\sprintf('%o', \fileperms($fullpath)), -3) !== \decoct($perms['folder'])) {
                            \fwrite($myfile, $this->l('Permission') . ' ' . Tools::substr(\decoct(\fileperms($fullpath)), -3) . ': ' . $fullpath . \PHP_EOL);

                            $this->chmodFileFolderAnalyze($fullpath);
                        }
                    }
                }
            }
            \fclose($myfile);
            \closedir($dh);
        }
    }

    /**
     * Block custom list of IP addresses.
     *
     * @param string $ip
     *
     * @return bool
     */
    private function blockIp()
    {
        $conf = (int) Configuration::get('LITE_BAN_IP_ACTIVATE');
        if (3 === $conf) {
            if ('1' === $this->context->cookie->__get('securityliteRecaptcha')) {
                return false;
            }
        }

        if (false === (bool) Configuration::get('LITE_BAN_IP')) {
            return false;
        }

        $blacklist = \explode(',', Configuration::get('LITE_BAN_IP'));
        foreach ($blacklist as &$list) {
            $range = \IPLib\Factory::rangeFromString($list);
            if ($range->contains(\IPLib\Factory::addressFromString(\Tools::getRemoteAddr()))) {
                $this->vulnDetectedHtml(
                    null,
                    $this->l('Block IP'),
                    $conf
                );
            }
        }

        return false;
    }

    /**
     * Check if Google IP.
     *
     * @return bool
     */
    private function validateGoogleBotIp()
    {
        $userAgent = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '';

        if (!empty($userAgent)) {
            if (\preg_match('/Google/', $userAgent)) {
                $hostname = \gethostbyaddr(\Tools::getRemoteAddr());

                return \preg_match('/\.googlebot\.com$/i', $hostname); // True if Google
            }
        }

        return false; // Not Google
    }

    /**
     * Block custom list of User agents.
     *
     * @return bool
     */
    private function blockUserAgent()
    {
        $conf = (int) Configuration::get('LITE_BLOCK_USER_AGENT_ACTIVATE');
        if (3 === $conf) {
            if ('1' === $this->context->cookie->__get('securityliteRecaptcha')) {
                return false;
            }
        }

        $userAgent = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '';

        if (!empty($_SERVER['HTTP_USER_AGENT'])) {
            $userAgent = $_SERVER['HTTP_USER_AGENT'];
            $blacklist = \explode(',', Configuration::get('LITE_BLOCK_USER_AGENT'));
            foreach ($blacklist as &$list) {
                if (false !== \mb_strpos($userAgent, $list)) {
                    $this->vulnDetectedHtml(
                        null,
                        $this->l('Block UA'),
                        $conf
                    );
                }
            }
        }

        return false;
    }

    /**
     * Whitelist IP addresses.
     *
     * @param $field string
     *
     * @return bool
     */
    private function checkWhitelist($field)
    {
        if (false === (bool) Configuration::get($field)) {
            return false;
        }
        $whitelist = \explode(',', Configuration::get($field));
        foreach ($whitelist as &$list) {
            $range = \IPLib\Factory::rangeFromString($list);
            if ($range->contains(\IPLib\Factory::addressFromString(\Tools::getRemoteAddr()))) {
                return true;
            }
        }

        return false;
    }

    /**
     * Ban user.
     */
    private function ban()
    {
        $this->context->employee->logout();
        exit;
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
            $result[] = $rootPath;
        }

        $modulePath = _PS_MODULE_DIR_;

        $iter = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($modulePath, RecursiveDirectoryIterator::SKIP_DOTS),
            RecursiveIteratorIterator::SELF_FIRST,
            RecursiveIteratorIterator::CATCH_GET_CHILD // Ignore "Permission denied"
        );

        foreach ($iter as $dir) {
            if ($dir->isDir()) {
                if ('phpunit' === $dir->getFilename()) {
                    $result[] = $dir->getRealpath();
                }
            }
        }

        return $result;
    }

    private function getFilePathExt($dir)
    {
        $files = \glob($dir . \DIRECTORY_SEPARATOR . '*.{7z,bz2,gz,rar,sql,tar,tgz,zip}', \GLOB_BRACE);
        $result = [];
        foreach ($files as $file) {
            $result[] = \realpath($file);
        }

        return $result;
    }

    /**
     * Get path to log file.
     *
     * @param string $fileName
     *
     * @return string
     */
    private function getLogFile($fileName)
    {
        if (Tools::version_compare(_PS_VERSION_, '1.7.0.0', '<')) {
            $path = '/log/';
        } elseif (Tools::version_compare(_PS_VERSION_, '1.7.3.0', '<=')) {
            $path = '/app/logs/';
        } else {
            $path = '/var/logs/';
        }

        $logPath = _PS_CORE_DIR_ . $path . $fileName;

        if (!\file_exists($logPath)) {
            \file_put_contents($logPath, '');
        }

        return $logPath;
    }

    /**
     * Download file.
     *
     * @param string $filePath
     * @param bool $deleteFile
     *
     * @return bool|null
     */
    private function downloadFile($filePath, $deleteFile = false)
    {
        if (\file_exists($filePath)) {
            \header('Content-Description: File Transfer');
            \header('Content-Type: application/x-octet-stream');
            \header('Content-Disposition: attachment; filename="' . \basename($filePath) . '"');
            \header('Expires: 0');
            \header('Cache-Control: must-revalidate');
            \header('Pragma: public');
            \header('Content-Length: ' . \filesize($filePath));
            \flush(); // Flush system output buffer
            \readfile($filePath);

            if (true === $deleteFile) {
                Tools::deleteFile($filePath);
            }

            exit;
        }

        return false;
    }

    /**
     * Response HTTP header 403 and block the request.
     *
     * @param int $code
     */
    private function blockRequest($code)
    {
        \http_response_code($code);
        \header('Connection: Close');
        \header('Cache-Control: max-age=0, private, no-store, no-cache, must-revalidate');

        $lang = $this->context->language->iso_code;

        echo '<!DOCTYPE html><html lang="' . $lang . '"> <head> <meta charset="utf-8"> <meta http-equiv="X-UA-Compatible" content="IE=edge"> <meta name="viewport" content="width=device-width, initial-scale=1"> <title>' . $this->l('Error') . ' ' . $code . '</title> ' . $this->getFavicon() . ' <style>*{font-size: 14px; text-rendering: optimizeLegibility; user-select: none;}body{color: #191919; background: #eff1f2; font-family: "Roboto", Helvetica, Arial, sans-serif; line-height: 1.6; font-size: 1em; padding: 0 20px;}#wrapper{width: 410px; height: 350px; margin: 0 auto; position: absolute; top: 50%; left: 50%; margin-top: -175px; margin-left: -205px;}.content{width: 100%; margin: 0 auto; text-align: center;}h1{font-weight: 300; font-size: 1.5em; color: #000;}p{line-height: 1em; font-weight: 300; color: #333;}.grid{max-width: 175px; height: 200px; background: #222; margin: 0 auto; padding: 1em 0; border-radius: 3px;}.grid .server{display: block; max-width: 68%; height: 20px; background: rgba(255,255,255,.15); box-shadow: 0 0 0 1px black inset; margin: 10px 0 20px 30px;}.grid .server:before{content: ""; position: relative; top: 7px; left: -18px; display: block; width: 6px; height: 6px; background: #78d07d; border: 1px solid black; border-radius: 6px; margin-top: 7px;}@-webkit-keyframes pulse{0%{background: rgba(255,255,255,.15);}100%{background: #ae1508;}}.grid .server:nth-child(3):before{background: rgba(255,255,255,.15); -webkit-animation: pulse .5s infinite alternate;}@-webkit-keyframes pulse_three{0%{background: rgba(255,255,255,.15);}100%{background: #d2710a;}}.grid .server:nth-child(5):before{background: rgba(255,255,255,.15); -webkit-animation: pulse_three .7s infinite alternate;}@-webkit-keyframes pulse_two{0%{background: rgba(255,255,255,.15);}100%{background: #9da506;}}.grid .server:nth-child(1):before{background: rgba(255,255,255,.15); -webkit-animation: pulse_two .1s infinite alternate;}.grid .server:nth-child(2):before{background: rgba(255,255,255,.15); -webkit-animation: pulse_two .175s infinite alternate;}.grid .server:nth-child(4):before{background: rgba(255,255,255,.15); -webkit-animation: pulse_two .1s infinite alternate;}</style> </head> <body> <div id="wrapper"> <div class="grid"> <span class="server"></span> <span class="server"></span> <span class="server"></span> <span class="server"></span> <span class="server"></span> </div><div class="content"> <h1>' . $this->l('Permission denied!') . '</h1> <p>' . $this->l('Error') . ' ' . $code . '</p></div></div></body></html>';
        exit;
    }

    /**
     * Normalize php ini value.
     *
     * @param string $v
     *
     * @return string
     */
    private function isOn($v)
    {
        if ('0' === $v || 'off' === Tools::strtolower($v) || '' === $v) {
            return '0';
        }

        return '1';
    }

    /**
     * Scan for open ports.
     *
     * @return array
     */
    private function portScanner()
    {
        $host = \Tools::getHttpHost(false, false, true);
        $ports = [
            20,
            21,
            22,
            23,
            25,
            53,
            80,
            110,
            119,
            135,
            137,
            138,
            139,
            143,
            443,
            445,
            465,
            520,
            587,
            993,
            995,
            1027,
            1433,
            1434,
            1457,
            1521,
            1723,
            2082,
            2086,
            2095,
            3306,
            3389,
            5060,
            5900,
            8080,
            8443,
            9100,
        ];
        $response = [];

        foreach ($ports as $port) {
            $connection = @\fsockopen($host, $port, $errno, $errstr, 2);

            $serv = \getservbyport($port, 'tcp');
            if (!empty($serv)) {
                $name = ' (' . $serv . ') ';
            } else {
                $name = ' ';
            }
            if (\is_resource($connection)) {
                $response[] = $host . ':' . $port . $name . $this->l('is open') . '.';

                \fclose($connection);
            } else {
                $response[] = $host . ':' . $port . $name . $this->l('is closed') . '.';
            }
        }

        \file_put_contents(_PS_MODULE_DIR_ . self::REPORT_PORT_SCANNER, \implode(\PHP_EOL, $response), \FILE_APPEND | \LOCK_EX);
    }

    /**
     * Make the Honeypot query (Honeypot API).
     *
     * @param string $ip
     *
     * @return int
     */
    private function honeypotQuery($ip)
    {
        $response = \explode('.', \gethostbyname(Configuration::get('LITE_HONEYPOT_API') . '.' . \implode('.', \array_reverse(\explode('.', $ip))) . '.dnsbl.httpbl.org'));

        if ('127' !== (string) $response[0]) {
            return false; // Not a threat
        }

        return (int) $response[3];
    }

    /**
     * Check if the client is a bot (Honeypot API).
     *
     * @param string $ip
     *
     * @return bool
     */
    private function isBot($ip)
    {
        $honeypotQuery = $this->honeypotQuery($ip);
        if (false !== $honeypotQuery) {
            if (0 === $honeypotQuery) {
                return false;
            }

            return true;
        }

        return false;
    }

    /**
     * Check if the IP is a TOR.
     *
     * @param string $ip
     *
     * @return bool
     */
    private function isTorExitPoint($ip)
    {
        $url = 'https://check.torproject.org/torbulkexitlist';

        $content = $this->getCachedRemoteContent($url, null, 'tor', 86400);

        if (false !== \strpos($content, $ip)) {
            return true; // Is tor
        }

        return false; // Is not tor
    }

    /**
     * Generate link for cronjob.
     *
     * @param string $name
     * @param bool $simple
     *
     * @return string
     */
    private function generateCronLink($name, $simple = false)
    {
        $token = $this->encrypt('securitylite/cron');
        $link = $this->context->link->getModuleLink('securitylite', 'cron', ['name' => $name, 'token' => $token]);

        if (true === $simple) {
            return $link;
        }

        $content = 'wget -q -O - "' . $link . '" >/dev/null 2>&1';

        return \htmlentities($content);
    }

    /**
     * Generate unlock link for Admin Stealth Login.
     *
     * @return string
     */
    private function generateUnlockLink()
    {
        $token = $this->encrypt('securitylite/unlock');
        $link = \htmlentities($this->context->link->getModuleLink('securitylite', 'unlock', ['token' => $token]));

        return '<kbd>' . $link . '</kbd> <a href="javascript:void(0)" onclick="copyToClipboard(\'' . $link . '\')"><i class="icon icon-clipboard"></i></a>';
    }

    /**
     * Check if PrestaShop is up to date.
     *
     * @return bool
     */
    private function checkPrestaShopUpToDate()
    {
        $url = 'https://api.prestashop.com/version/check_version.php';

        $params = [
            'v' => _PS_VERSION_,
            'lang' => $this->context->language->iso_code,
            'autoupgrade' => '0',
            'hosted_mode' => '0',
        ];

        $content = $this->getCachedRemoteContent($url, $params, 'ps_version', 86400);
        if (false === $content) {
            return true; // Error
        }

        if (false !== \mb_strpos($content, 'btn-default')) {
            return true; // Not up to date
        }

        return false; // Up to date
    }

    /**
     * Get an array of trusted / untrusted modules.
     *
     * @param bool $trusted
     *
     * @return array
     */
    private function getModules($trusted)
    {
        if (true === $trusted) {
            $path = _PS_ROOT_DIR_ . '/config/xml/trusted_modules_list.xml';
        } else {
            $path = _PS_ROOT_DIR_ . '/config/xml/untrusted_modules_list.xml';
        }
        if (!\file_exists($path)) {
            ModuleCore::generateTrustedXml();
        }
        $xml = \simplexml_load_string(Tools::file_get_contents($path));

        if (!empty($xml->modules)) {
            $modules = [];
            foreach ($xml->modules->module as $module) {
                if (Module::isInstalled($module['name'])) {
                    $modules[] = $module['name'];
                }
            }

            return \array_unique($modules);
        }
    }

    /**
     * Get newest PHP version.
     *
     * @param string $currentVersion
     *
     * @return string
     */
    private function getNewestPhpVersion($currentVersion)
    {
        $url = 'https://www.php.net/releases/';

        $params = [
            'json' => '1',
            'version' => $currentVersion,
        ];

        $content = $this->getCachedJsonDecodedContent($url, $params, $currentVersion, 3600);

        return $content['version'];
    }

    /**
     * Return distance in km.
     *
     * @param float $lat1
     * @param float $lon1
     * @param float $lat2
     * @param float $lon2
     * @param string $unit
     *
     * @return float
     */
    private function getDistance($lat1, $lon1, $lat2, $lon2, $unit)
    {
        if (($lat1 === $lat2) && ($lon1 === $lon2)) {
            return 0;
        }

        $theta = $lon1 - $lon2;
        $dist = \sin(\deg2rad($lat1)) * \sin(\deg2rad($lat2)) + \cos(\deg2rad($lat1)) * \cos(\deg2rad($lat2)) * \cos(\deg2rad($theta));
        $dist = \acos($dist);
        $dist = \rad2deg($dist);

        if ('km' === $unit) {
            $factor = 1;
        } elseif ('mi' === $unit) {
            $factor = 0.621371;
        }

        return (float) \round($dist * 60 * 1.1515 * 1.609344 * $factor, 1);
    }

    /**
     * Download content with cURL.
     *
     * @param string $url
     * @param array|null $params
     *
     * @return false|string
     */
    private function getRemoteContent($url, $params = null)
    {
        $options = [
            \CURLOPT_URL => (null !== $params) ? \sprintf('%s?%s', $url, \http_build_query($params)) : $url,
            \CURLOPT_RETURNTRANSFER => true,
            \CURLOPT_HEADER => false,
            \CURLOPT_FOLLOWLOCATION => true,
            \CURLOPT_ENCODING => '',
            \CURLOPT_USERAGENT => '',
            \CURLOPT_REFERER => '',
            \CURLOPT_CONNECTTIMEOUT => 5,
            \CURLOPT_TIMEOUT => 5,
            \CURLOPT_MAXREDIRS => 5,
            \CURLOPT_SSL_VERIFYPEER => false,
            \CURLOPT_IPRESOLVE => \CURL_IPRESOLVE_V4,
        ];

        $ch = \curl_init();
        \curl_setopt_array($ch, $options);
        $content = \curl_exec($ch);
        $error = \curl_error($ch);
        \curl_close($ch);

        if (true === (bool) $error) {
            return false; // Error
        }

        return $content;
    }

    /**
     * Convert size to bytes.
     *
     * @param string $sizeStr
     *
     * @return int
     */
    private function convertToBytes($sizeStr)
    {
        $type = Tools::substr(\mb_strtolower($sizeStr), -1);
        switch ($type) {
            case 'm':
                return (int) $sizeStr * 1048576;
            case 'k':
                return (int) $sizeStr * 1024;
            case 'g':
                return (int) $sizeStr * 1073741824;

            default:
                return (int) $sizeStr;
        }
    }

    /**
     * Get montastic ids.
     *
     * @return array
     */
    private function getMontasticIds()
    {
        $ch = \curl_init();

        \curl_setopt($ch, \CURLOPT_URL, 'https://montastic.com/checkpoints');
        \curl_setopt($ch, \CURLOPT_RETURNTRANSFER, 1);
        \curl_setopt($ch, \CURLOPT_CUSTOMREQUEST, 'GET');

        $headers = [];
        $headers[] = 'X-Api-Key: ' . Configuration::get('LITE_MONTASTIC_API');
        $headers[] = 'Accept: application/json';
        \curl_setopt($ch, \CURLOPT_HTTPHEADER, $headers);

        $result = \curl_exec($ch);
        \curl_close($ch);

        $arr = \json_decode($result, true);

        $ids = [];
        foreach ($arr as $id) {
            $ids[] = $id['id'];
        }

        return $ids;
    }

    /**
     * Get monastic data.
     *
     * @param int $id
     *
     * @return array
     */
    private function getMontasticData($id)
    {
        $ch = \curl_init();

        \curl_setopt($ch, \CURLOPT_URL, "https://montastic.com/checkpoints/$id");
        \curl_setopt($ch, \CURLOPT_RETURNTRANSFER, 1);
        \curl_setopt($ch, \CURLOPT_CUSTOMREQUEST, 'GET');

        $headers = [];
        $headers[] = 'X-Api-Key: ' . Configuration::get('LITE_MONTASTIC_API');
        $headers[] = 'Accept: application/json';
        \curl_setopt($ch, \CURLOPT_HTTPHEADER, $headers);

        $result = \curl_exec($ch);
        \curl_close($ch);

        return \json_decode($result, true);
    }

    /**
     * Check if OS is windows.
     *
     * @return bool
     */
    private function isWindowsOs()
    {
        return (0 === \mb_stripos(\PHP_OS, 'WIN')) ? true : false;
    }

    /**
     * Cache a json request. Default cache-time is 24 hours.
     *
     * @param string $url
     * @param array $params
     * @param string $name
     * @param int $cacheTime
     *
     * @return array
     */
    private function getCachedJsonDecodedContent($url, $params, $name, $cacheTime = 86400)
    {
        $cachePath = _PS_CACHE_DIR_ . 'securitylite';
        $filename = $cachePath . \DIRECTORY_SEPARATOR . $this->encrypt($name) . '.json';

        if (\file_exists($filename) && (\time() - $cacheTime < \filemtime($filename))) {
            return \json_decode(Tools::file_get_contents($filename), true);
        }

        $content = $this->getRemoteContent($url, $params);

        if (false === $this->isJson($content)) {
            return false; // Error
        }

        if (false !== $content) {
            if (!\is_dir($cachePath)) {
                \mkdir($cachePath, 0755, true);
                $this->addIndexRecursively($cachePath);
                \file_put_contents($cachePath . '/.htaccess', $this->getHtaccessContent());
            }
            \file_put_contents($filename, $content); // Save cache

            return \json_decode($content, true);
        }

        if (\file_exists($filename)) {
            return \json_decode(Tools::file_get_contents($filename), true); // If the response is false, we want to use the cached version even though it is outdated.
        }

        return false; // If the connection fails to the API and no cache is stored.
    }

    /**
     * Cache a request. Default is cache time is 24 hours.
     *
     * @param string $url
     * @param array $params
     * @param string $name
     * @param int $cacheTime
     *
     * @return array
     */
    private function getCachedRemoteContent($url, $params, $name, $cacheTime = 86400)
    {
        $cachePath = _PS_CACHE_DIR_ . 'securitylite';
        $filename = $cachePath . \DIRECTORY_SEPARATOR . $this->encrypt($name) . '.txt';

        if (\file_exists($filename) && (\time() - $cacheTime < \filemtime($filename))) {
            return Tools::file_get_contents($filename);
        }

        $content = $this->getRemoteContent($url, $params);

        if (false !== $content) {
            if (!\is_dir($cachePath)) {
                \mkdir($cachePath, 0755, true);
                $this->addIndexRecursively($cachePath);
                \file_put_contents($cachePath . '/.htaccess', $this->getHtaccessContent());
            }
            \file_put_contents($filename, $content); // Save cache

            return $content;
        }

        if (\file_exists($filename)) {
            return Tools::file_get_contents($filename); // If the response is false, we want to use the cached version even though it is outdated.
        }

        return false; // If the connection fails to the API and no cache is stored.
    }

    /**
     * Check if string is valid json.
     *
     * @param string $string
     *
     * @return bool
     */
    private function isJson($string)
    {
        \json_decode($string);

        return \JSON_ERROR_NONE === \json_last_error();
    }

    /**
     * Get size of directories.
     *
     * @param array $paths
     *
     * @return int
     */
    private function getDirectorySize($paths)
    {
        $bytestotal = 0;
        foreach ($paths as $path) {
            $path = \realpath($path);
            if (!empty($path) && \file_exists($path)) {
                foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($path, FilesystemIterator::SKIP_DOTS)) as $object) {
                    if ('index.php' !== $object->getFilename() && '.htaccess' !== $object->getFilename()) {
                        $bytestotal += $object->getSize();
                    }
                }
            }
        }

        return $bytestotal;
    }

    /**
     * Clear cache of securitylite.
     *
     * @param bool $clearTable
     */
    private function clearCacheSecuritylite($clearTable = true)
    {
        // Clear cache of folders
        $folders = [
            _PS_CACHE_DIR_ . 'securitylite',
        ];
        foreach ($folders as $folder) {
            if (\is_dir($folder)) {
                foreach (new DirectoryIterator($folder) as $fileInfo) {
                    if (!$fileInfo->isDot()) {
                        Tools::deleteFile($fileInfo->getPathname(), ['index.php', '.htaccess']);
                    }
                }
            }
        }

        // Regenerate XML
        ModuleCore::generateTrustedXml();

        // Clear table
        if (true === $clearTable) {
            $query = 'TRUNCATE TABLE `' . _DB_PREFIX_ . 'securitylite`';
            Db::getInstance()->execute($query);
        }
    }

    /**
     * Get array of employees information.
     *
     * @param bool $activeOnly
     *
     * @return array
     */
    private function getEmployees($activeOnly = true)
    {
        return Db::getInstance()->executeS('
            SELECT `id_employee`, `firstname`, `lastname`, `email`, `passwd`, `last_passwd_gen`, `last_connection_date`, `active` 
            FROM `' . _DB_PREFIX_ . 'employee`
            ' . ($activeOnly ? ' WHERE `active` = 1' : '') . '
            ORDER BY `lastname` ASC
        ');
    }

    /**
     * Generate TFA token.
     *
     * @return string
     */
    private function getTfaToken()
    {
        $employees = $this->getEmployees(true);

        $tfaToken = [];
        foreach ($employees as $employee) {
            $tfaToken[] = $this->encrypt($employee['passwd']);
        }

        return $tfaToken;
    }

    /**
     * Generate RBL report.
     */
    private function generateReportRbl()
    {
        $serverIp = $_SERVER['SERVER_ADDR'];

        $url = 'https://rbl-check.org/rbl_api.php?ipaddress=' . $serverIp;

        //Open the file.
        $fileHandle = \fopen($url, 'rb');

        //Loop through the CSV rows.
        $response = [];
        while (false !== ($row = \fgetcsv($fileHandle, 0, ';'))) {
            $rbl = $row[0];
            $host = $row[1];
            if ('listed' === $row[3]) {
                $status = $this->l('You are listed in');
            } elseif ('notlisted' === $row[3]) {
                $status = $this->l('You are not listed in');
            }

            if (isset($rbl, $host, $status)) {
                $response[] = $status . ' ' . $rbl . ' (' . $host . ')';
            }
        }

        \fclose($url);

        \file_put_contents(_PS_MODULE_DIR_ . self::REPORT_RBL_CHECKER, \implode(\PHP_EOL, $response), \FILE_APPEND | \LOCK_EX);
    }

    /**
     * Get employee admin link.
     *
     * @param string $id
     *
     * @return string
     */
    private function getEmployeeAdminLink($id)
    {
        if (Tools::version_compare(_PS_VERSION_, '1.7.6.0', '<')) { // < 1.7.6
            $url = $this->getAdminLink('AdminEmployees', true) . '&id_employee=' . $id . '&updateemployee';
        } else { // >= 1.7.6
            $explode = \explode('?', $this->getAdminLink('AdminEmployees', true));
            $url = $explode[0] . $id . '/edit?' . $explode[1];
        }

        return $url;
    }

    /**
     * Get admin link.
     *
     * @param string $controller
     * @param bool $withToken
     *
     * @return string
     */
    private function getAdminLink($controller, $withToken = true)
    {
        if (Tools::version_compare(_PS_VERSION_, '1.7.0.0', '>=')) { // 1.7
            return $this->context->link->getAdminLink($controller, $withToken);
        }

        // 1.6
        return $this->getBaseURL() . \basename(_PS_ADMIN_DIR_) . '/' . $this->context->link->getAdminLink($controller, $withToken);
    }

    /**
     * Check if SSL/TLS is enabled.
     *
     * @return bool
     */
    private function isSsl()
    {
        // Check if SSL is enabled
        if (false === (bool) Configuration::get('PS_SSL_ENABLED')) {
            return false;
        }

        // Check if port 433 is open
        if (isset($_SERVER['SERVER_PORT']) && '443' !== $_SERVER['SERVER_PORT']) {
            return false;
        }

        return true;
    }

    private function addHeading($content, $noTop = false)
    {
        if (true === $noTop) {
            return '<h2 style="margin-top: -10px">' . $content . '</h2>';
        }

        return '<h2>' . $content . '</h2>';
    }

    private function addAlertWarning($content)
    {
        return '<div class="alert alert-warning">' . $content . '</div>';
    }

    private function addAlertInfo($content)
    {
        return '<div class="alert alert-info">' . $content . '</div>';
    }
}
