/**
 * This file is part of the securitypro package.
 *
 * @author Mathias Reker
 * @copyright Mathias Reker
 * @license Commercial Software License
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

$(document).on("contextmenu","img",function(e){"INPUT"!=e.target.nodeName&&"TEXTAREA"!=e.target.nodeName&&e.preventDefault()});
