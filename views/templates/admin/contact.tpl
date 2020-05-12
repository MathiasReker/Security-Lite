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
    <h3><i class="icon-envelope-o"></i> {l s='Contact developer' mod='securitylite'}</h3>
    <div>
        <p>{l s='Want to upgrade to Security Pro? Only 69,99€ excl. tax as an onetime fee! Free support!' mod='securitylite'}</p>
        <a class="btn btn-primary" href="https://addons.prestashop.com/en/website-security-access/44413-security-pro-all-in-one.html" target="_blank" rel="noopener noreferrer">{l s='Upgrade now' mod='securitylite'}</a> <a class="btn btn-default" href="https://addons.prestashop.com/en/website-security-access/44413-security-pro-all-in-one.html" target="_blank" rel="noopener noreferrer">{l s='Read more' mod='securitylite'}</a>
    </div>
    <br>
    <div>
        <p>{l s='Questions?' mod='securitylite'}</p>
        <a class="btn btn-default" href="{$contactUrl|escape:'htmlall':'UTF-8'}" target="_blank" rel="noopener noreferrer">{l s='Contact module developer' mod='securitylite'}</a>
    </div>
    <br>
    <div>
    <p>{l s='Would you like to translate this module into your language or improve the wording?' mod='securitylite'}</p>
    <ul>
    <li>{l s='Click on "Translate" (flag icon) in the upper right corner' mod='securitylite'}</li>
    <li>{l s='Choose a language' mod='securitylite'}</li>
    <li>{l s='Make your changes and save' mod='securitylite'}</li>
    </ul>
        <p>{l s='If you do any improvements to the wording, please export your translation and send it to the module developer, so your improvements can be merged into the next release. Your contribution is appreciated!' mod='securitylite'}</p>
        <form id="" action="{$currentUrl|escape:'htmlall':'UTF-8'}&transDownload=1" method="POST">
            <input type="submit" class="btn btn-default" id="btnFiles" value="{l s='Export translations' mod='securitylite'}"></input>
        </form>
    </div>
</div>
