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
    <h3><i class="icon-file-code-o"></i> {l s='Scripts' mod='securitylite'}</h3>
    <div>
        <p>{l s='Run this script to quickly find open ports on your network. If you have unused open ports you should consider to close them.' mod='securitylite'} {l s='Running this script might take 1-2 minutes. Please be patient.' mod='securitylite'}</p>
        <form id="formPortScanner" action="{$currentUrl|escape:'htmlall':'UTF-8'}&btnPortScanner=1" method="POST">
            <input type="submit" class="btn btn-default" id="btnPortScanner" value="{l s='Run port scanner' mod='securitylite'}"></input>
        </form>
        <br>
        <p>{l s='Change file permissions to 644 and directory permissions to 755. This is highly recommended!' mod='securitylite'} {l s='Running this script might take 1-2 minutes. Please be patient.' mod='securitylite'}</p>
        <form id="formPermissions" action="{$currentUrl|escape:'htmlall':'UTF-8'}&btnPermissions=1" method="POST">
            <input type="submit" class="btn btn-default" id="btnPermissions" value="{l s='Fix insecure file- and directory permissions' mod='securitylite'}"></input>
        </form>
        <br>
        <p>{l s='Fix directory traversal (observing) security vulnerability. This script adds missing index.php files to theme- and module directories. This is highly recommended!' mod='securitylite'} {l s='Running this script might take 1-2 minutes. Please be patient.' mod='securitylite'}</p>
        <form id="formIndex" action="{$currentUrl|escape:'htmlall':'UTF-8'}&btnIndex=1" method="POST">
            <input type="submit" class="btn btn-default" id="btnIndex" value="{l s='Add missing index.php files' mod='securitylite'}"></input>
        </form>
        {if $show eq '1'}
        <br>
        <p>{l s='It is highly recommended to remove following files/directories:' mod='securitylite'}</p>
        <ul>
            {foreach from=$elements item=element}
                <li>{$element|escape:'htmlall':'UTF-8'}</li>
            {/foreach}
        </ul>
        <form id="formFiles" action="{$currentUrl|escape:'htmlall':'UTF-8'}&btnFiles=1" method="POST">
            <input type="submit" class="btn btn-default" id="btnFiles" value="{l s='Remove files/directories' mod='securitylite'}"></input>
        </form>
        {/if}
    </div>
</div>

<script>
    $(document).ready(function() {
        $("#btnPortScanner").attr("disabled", true);
        $("#formPermissions").submit(function(e) {
            $("#btnPermissions").attr("disabled", true);
            $("#btnPermissions").attr("value", "{l s='Please wait' mod='securitylite'} ...");
            return true;
        });
        $("#btnIndex").attr("disabled", true);
        $("#formFiles").submit(function(e) {
            $("#btnFiles").attr("disabled", true);
            $("#btnFiles").attr("value", "{l s='Please wait' mod='securitylite'} ...");
            return true;
        });
    });
</script>
