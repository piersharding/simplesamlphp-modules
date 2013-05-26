<?php
/**
 * authigovt: SimpleSAMLphp NZ Post Attribute Query Service proxy for
 * the Address Verification Service
 *
 * Copyright (C) 2012-2013 Catalyst IT Ltd and Piers Harding
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * @package    SimpleSAMLphp
 * @subpackage authigovt
 * @author     Catalyst IT Ltd
 * @author     Piers Harding
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL
 * @copyright  (C) 2012-2013 Catalyst IT Ltd http://catalyst.net.nz
 *
 *
 * Link the iGovt FLT to an existing LDAP user account
 */

if (!is_string($_REQUEST['AuthState'])) {
	throw new SimpleSAML_Error_BadRequest('Missing AuthState-parameter.');
}
$authStateId = $_REQUEST['AuthState'];

/* Retrieve the authentication state. */
$state = SimpleSAML_Auth_State::loadState($authStateId, 'authigovt:state');

$session = new sspmod_authigovt_SessionStore();
$login = $session->get('Login');

if (isset($_REQUEST['ConfirmYes'])) {

    // link account in LDAP
    $authsource = SimpleSAML_Configuration::getConfig('authsources.php');
    $igovtauthsource = $authsource->getConfigItem($state['authigovt:AuthId']);
    $ldapid = $igovtauthsource->getValue('loginauthid');
    $ldapsource = $authsource->getConfigItem($ldapid);
    $igovtauthsource = $igovtauthsource->toArray();
    $as = new sspmod_authigovt_Auth_Source_iGovt(array('AuthId' => $ldapid), $igovtauthsource);

    // Search
    $hostname = $ldapsource->getString('hostname');
    $enableTLS = $ldapsource->getBoolean('enable_tls', FALSE);
    $debug = $ldapsource->getBoolean('debug', FALSE);
    $timeout = $ldapsource->getInteger('timeout', 0);
    $searchBase = $ldapsource->getArrayizeString('search.base');
    $searchAttributes = $ldapsource->getArray('search.attributes');
    $ldap = new SimpleSAML_Auth_LDAP($hostname,
                    $enableTLS,
                    $debug,
                    $timeout);
    $dn = $ldap->searchfordn($searchBase, $searchAttributes, $login['username'], TRUE);

    // Bind to LDAP
    $ds = $as->bindLdap();

    // update user with link
    $mod_user = array($igovtauthsource['linkattr'] => array($login['igovtid']));

    if(!ldap_modify($ds, $dn, $mod_user)) {
        echo "user update failed: ".var_export($mod_user, true);
        var_dump($dn);
        die();
    }

    $redirect = SimpleSAML_Module::getModuleURL('authigovt/callback.php');
    SimpleSAML_Utilities::redirect($redirect);
    die();
}

if (isset($_REQUEST['ConfirmNo'])) {
    // redirect back to login attempt
    $url = SimpleSAML_Module::getModuleURL('authigovt/loginuserpass.php');
    SimpleSAML_Utilities::redirect($url, array('AuthState' => $authStateId));
}

$globalConfig = SimpleSAML_Configuration::getInstance();
$t = new SimpleSAML_XHTML_Template($globalConfig, 'authigovt:link.tpl.php');
$t->data['AuthState'] = $_REQUEST['AuthState'];
$t->data['igovtid'] = $login['igovtid'];
$t->data['username'] = $login['username'];
$t->show();
