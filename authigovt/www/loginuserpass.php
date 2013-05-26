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
 */

/**
 * Copied from the existing LDAP login page from core - modified to store details of 
 * LDAP login for subsequent linking
 *
 * This page shows a username/password login form, and passes information from it
 * to the sspmod_core_Auth_UserPassBase class, which is a generic class for
 * username/password authentication.
 *
 * @author Olav Morken, UNINETT AS.
 * @package simpleSAMLphp
 * @version $Id$
 */

if (!array_key_exists('AuthState', $_REQUEST)) {
	throw new SimpleSAML_Error_BadRequest('Missing AuthState parameter.');
}
$authStateId = $_REQUEST['AuthState'];

/* Retrieve the authentication state. */
$state = SimpleSAML_Auth_State::loadState($authStateId, 'authigovt:state');
$authsource = SimpleSAML_Configuration::getConfig('authsources.php');
$authsource = $authsource->getConfigItem($state['authigovt:AuthId']);
$authid = $authsource->getValue('loginauthid');

$source = SimpleSAML_Auth_Source::getById($authid);
if ($source === NULL) {
	throw new Exception('Could not find authentication source with id ' . $authid);
}

if (array_key_exists('username', $_REQUEST)) {
	$username = $_REQUEST['username'];
} elseif ($source->getRememberUsernameEnabled() && array_key_exists($source->getAuthId() . '-username', $_COOKIE)) {
	$username = $_COOKIE[$source->getAuthId() . '-username'];
} elseif (isset($state['core:username'])) {
	$username = (string)$state['core:username'];
} else {
	$username = '';
}

if (array_key_exists('password', $_REQUEST)) {
	$password = $_REQUEST['password'];
} else {
	$password = '';
}

if (!empty($_REQUEST['username']) || !empty($password)) {
	/* Either username or password set - attempt to log in. */

	if (array_key_exists('forcedUsername', $state)) {
		$username = $state['forcedUsername'];
	}

	if ($source->getRememberUsernameEnabled()) {
		$sessionHandler = SimpleSAML_SessionHandler::getSessionHandler();
		$params = $sessionHandler->getCookieParams();
		$params['expire'] = time();
		$params['expire'] += (isset($_REQUEST['remember_username']) && $_REQUEST['remember_username'] == 'Yes' ? 31536000 : -300);
		setcookie($source->getAuthId() . '-username', $username, $params['expire'], $params['path'], $params['domain'], $params['secure'], $params['httponly']);
	}

	try {
	    /* Attempt to log in. */
	    $session = new sspmod_authigovt_SessionStore();
	    $session->del('Login');
	    $attributes = $source->login($username, $password);
	    $session = new sspmod_authigovt_SessionStore();
	    $session->set('Login', array('igovtid' => $session->get('nameid'), 'username' => $username));
	    $url = SimpleSAML_Module::getModuleURL('authigovt/link.php');
	    SimpleSAML_Utilities::redirect($url, array('AuthState' => $authStateId));
	} catch (SimpleSAML_Error_Error $e) {
	    /*
	     * Login failed. Return the error code to the login form, so that it
	    * can display an error message to the user.
	    */
	    $errorCode = $e->getErrorCode();
	}
} else {
	$errorCode = NULL;
}

$globalConfig = SimpleSAML_Configuration::getInstance();
$t = new SimpleSAML_XHTML_Template($globalConfig, 'authigovt:loginuserpass.tpl.php');
$t->data['stateparams'] = array('AuthState' => $authStateId);
if (array_key_exists('forcedUsername', $state)) {
	$t->data['username'] = $state['forcedUsername'];
	$t->data['forceUsername'] = TRUE;
	$t->data['rememberUsernameEnabled'] = FALSE;
	$t->data['rememberUsernameChecked'] = FALSE;
} else {
	$t->data['username'] = $username;
	$t->data['forceUsername'] = FALSE;
	$t->data['rememberUsernameEnabled'] = $source->getRememberUsernameEnabled();
	$t->data['rememberUsernameChecked'] = $source->getRememberUsernameChecked();
	if (isset($_COOKIE[$source->getAuthId() . '-username'])) $t->data['rememberUsernameChecked'] = TRUE;
}
$t->data['links'] = $source->getLoginLinks();
$t->data['errorcode'] = $errorCode;

if (isset($state['SPMetadata'])) {
	$t->data['SPMetadata'] = $state['SPMetadata'];
} else {
	$t->data['SPMetadata'] = NULL;
}

$t->show();
exit();


?>