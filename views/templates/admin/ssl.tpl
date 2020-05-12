{*
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
*}

<div class="panel">
    <h3><i class="icon-lock"></i> {l s='Analyze SSL / TLS' mod='securitylite'}</h3>
    <div>
    {if $sslEnabled}
        <p><strong>{l s='Certificate' mod='securitylite'}</strong>: {$getIssuer|escape:'htmlall':'UTF-8'}</p>
        <p><strong>{l s='Verified by' mod='securitylite'}</strong>: {$getVarified|escape:'htmlall':'UTF-8'}</p>
        <p><strong>{l s='Expiration date' mod='securitylite'}</strong>: {$expirationDate|escape:'htmlall':'UTF-8'}</p>
        <p><strong>{l s='Expire in' mod='securitylite'}</strong>: {$diffInDays|escape:'htmlall':'UTF-8'} days</p>
        <p><strong>{l s='Signature algorithm' mod='securitylite'}</strong>: {$getSignatureAlgorithm|escape:'htmlall':'UTF-8'}</p>
        <p><strong>{l s='Version' mod='securitylite'}</strong>: {$getTlsVersion|escape:'htmlall':'UTF-8'}</p>
        <br>
        <p>{l s='Mixed content occurs when initial HTML is loaded over a secure HTTPS connection, but other resources (such as images, videos, stylesheets, scripts) are loaded over an insecure HTTP connection. This is called mixed content because both HTTP and HTTPS content are being loaded to display the same page, and the initial request was secure over HTTPS. Modern browsers display warnings about this type of content to indicate to the user that this page contains insecure resources.' mod='securitylite'}</p>
        <a id="MixedContentScanner" class="btn btn-default" href="{$mixedContentScannerUrl|escape:'htmlall':'UTF-8'}" target="_blank" rel="noopener noreferrer">{l s='Scan your website for mixed content' mod='securitylite'}</a>
    {else}
        <p>{l s='You must enable SSL to see this block.' mod='securitylite'}</p>
    {/if}
    </div>
</div>

<script>
    $(document).ready(function() {
        $("#MixedContentScanner").attr("disabled", true);
    });
</script>
