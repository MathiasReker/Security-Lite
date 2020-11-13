<?php

// autoload_static.php @generated by Composer

namespace Composer\Autoload;

class ComposerStaticInit6e410ad27b65f7365030aa1ea83fae7f
{
    public static $prefixLengthsPsr4 = array (
        'R' => 
        array (
            'RobThree\\Auth\\' => 14,
        ),
        'I' => 
        array (
            'IPLib\\' => 6,
        ),
    );

    public static $prefixDirsPsr4 = array (
        'RobThree\\Auth\\' => 
        array (
            0 => __DIR__ . '/..' . '/robthree/twofactorauth/lib',
        ),
        'IPLib\\' => 
        array (
            0 => __DIR__ . '/..' . '/mlocati/ip-lib/src',
        ),
    );

    public static $classMap = array (
        'DG\\ComposerCleaner\\Cleaner' => __DIR__ . '/..' . '/dg/composer-cleaner/src/ComposerCleaner/Cleaner.php',
        'DG\\ComposerCleaner\\Plugin' => __DIR__ . '/..' . '/dg/composer-cleaner/src/ComposerCleaner/Plugin.php',
        'IPLib\\Address\\AddressInterface' => __DIR__ . '/..' . '/mlocati/ip-lib/src/Address/AddressInterface.php',
        'IPLib\\Address\\AssignedRange' => __DIR__ . '/..' . '/mlocati/ip-lib/src/Address/AssignedRange.php',
        'IPLib\\Address\\IPv4' => __DIR__ . '/..' . '/mlocati/ip-lib/src/Address/IPv4.php',
        'IPLib\\Address\\IPv6' => __DIR__ . '/..' . '/mlocati/ip-lib/src/Address/IPv6.php',
        'IPLib\\Address\\Type' => __DIR__ . '/..' . '/mlocati/ip-lib/src/Address/Type.php',
        'IPLib\\Factory' => __DIR__ . '/..' . '/mlocati/ip-lib/src/Factory.php',
        'IPLib\\Range\\AbstractRange' => __DIR__ . '/..' . '/mlocati/ip-lib/src/Range/AbstractRange.php',
        'IPLib\\Range\\Pattern' => __DIR__ . '/..' . '/mlocati/ip-lib/src/Range/Pattern.php',
        'IPLib\\Range\\RangeInterface' => __DIR__ . '/..' . '/mlocati/ip-lib/src/Range/RangeInterface.php',
        'IPLib\\Range\\Single' => __DIR__ . '/..' . '/mlocati/ip-lib/src/Range/Single.php',
        'IPLib\\Range\\Subnet' => __DIR__ . '/..' . '/mlocati/ip-lib/src/Range/Subnet.php',
        'IPLib\\Range\\Type' => __DIR__ . '/..' . '/mlocati/ip-lib/src/Range/Type.php',
        'RobThree\\Auth\\Providers\\Qr\\BaseHTTPQRCodeProvider' => __DIR__ . '/..' . '/robthree/twofactorauth/lib/Providers/Qr/BaseHTTPQRCodeProvider.php',
        'RobThree\\Auth\\Providers\\Qr\\IQRCodeProvider' => __DIR__ . '/..' . '/robthree/twofactorauth/lib/Providers/Qr/IQRCodeProvider.php',
        'RobThree\\Auth\\Providers\\Qr\\ImageChartsQRCodeProvider' => __DIR__ . '/..' . '/robthree/twofactorauth/lib/Providers/Qr/ImageChartsQRCodeProvider.php',
        'RobThree\\Auth\\Providers\\Qr\\QRServerProvider' => __DIR__ . '/..' . '/robthree/twofactorauth/lib/Providers/Qr/QRServerProvider.php',
        'RobThree\\Auth\\Providers\\Qr\\QRicketProvider' => __DIR__ . '/..' . '/robthree/twofactorauth/lib/Providers/Qr/QRicketProvider.php',
        'RobThree\\Auth\\Providers\\Rng\\CSRNGProvider' => __DIR__ . '/..' . '/robthree/twofactorauth/lib/Providers/Rng/CSRNGProvider.php',
        'RobThree\\Auth\\Providers\\Rng\\HashRNGProvider' => __DIR__ . '/..' . '/robthree/twofactorauth/lib/Providers/Rng/HashRNGProvider.php',
        'RobThree\\Auth\\Providers\\Rng\\IRNGProvider' => __DIR__ . '/..' . '/robthree/twofactorauth/lib/Providers/Rng/IRNGProvider.php',
        'RobThree\\Auth\\Providers\\Rng\\MCryptRNGProvider' => __DIR__ . '/..' . '/robthree/twofactorauth/lib/Providers/Rng/MCryptRNGProvider.php',
        'RobThree\\Auth\\Providers\\Rng\\OpenSSLRNGProvider' => __DIR__ . '/..' . '/robthree/twofactorauth/lib/Providers/Rng/OpenSSLRNGProvider.php',
        'RobThree\\Auth\\Providers\\Time\\HttpTimeProvider' => __DIR__ . '/..' . '/robthree/twofactorauth/lib/Providers/Time/HttpTimeProvider.php',
        'RobThree\\Auth\\Providers\\Time\\ITimeProvider' => __DIR__ . '/..' . '/robthree/twofactorauth/lib/Providers/Time/ITimeProvider.php',
        'RobThree\\Auth\\Providers\\Time\\LocalMachineTimeProvider' => __DIR__ . '/..' . '/robthree/twofactorauth/lib/Providers/Time/LocalMachineTimeProvider.php',
        'RobThree\\Auth\\Providers\\Time\\NTPTimeProvider' => __DIR__ . '/..' . '/robthree/twofactorauth/lib/Providers/Time/NTPTimeProvider.php',
        'RobThree\\Auth\\TwoFactorAuth' => __DIR__ . '/..' . '/robthree/twofactorauth/lib/TwoFactorAuth.php',
        'RobThree\\Auth\\TwoFactorAuthException' => __DIR__ . '/..' . '/robthree/twofactorauth/lib/TwoFactorAuthException.php',
    );

    public static function getInitializer(ClassLoader $loader)
    {
        return \Closure::bind(function () use ($loader) {
            $loader->prefixLengthsPsr4 = ComposerStaticInit6e410ad27b65f7365030aa1ea83fae7f::$prefixLengthsPsr4;
            $loader->prefixDirsPsr4 = ComposerStaticInit6e410ad27b65f7365030aa1ea83fae7f::$prefixDirsPsr4;
            $loader->classMap = ComposerStaticInit6e410ad27b65f7365030aa1ea83fae7f::$classMap;

        }, null, ClassLoader::class);
    }
}
