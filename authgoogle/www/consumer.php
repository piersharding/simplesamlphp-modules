<?php
/* Add the OpenIDConnect library to the search path. */
set_include_path(get_include_path() . PATH_SEPARATOR . dirname(dirname(__FILE__)) . '/extlib');
require_once('OpenIDConnectClient.php5');

$config = SimpleSAML_Configuration::getInstance();

$returned = false;

/* Find the authentication state. */
if (!array_key_exists('AuthState', $_REQUEST)) {
    if (empty($_SESSION['openid_connect_AuthState'])) {
    	throw new SimpleSAML_Error_BadRequest('Missing mandatory state value: openid_connect_AuthState');
    }
    else {
        $authState = $_SESSION['openid_connect_AuthState'];
        unset($_SESSION['openid_connect_AuthState']);
        $returned = true;
    }
}
else {
    $authState = $_REQUEST['AuthState'];
}
$state = SimpleSAML_Auth_State::loadState($authState, 'authgoogle:state');
$authSource = SimpleSAML_Auth_Source::getById($state['authgoogle:AuthId']);
if ($authSource === NULL) {
	throw new SimpleSAML_Error_BadRequest('Invalid AuthId \'' . $state['authgoogle:AuthId'] . '\' - not found.');
}

try {
	if ($returned) {
		$authSource->postAuth($state);
	} else {
		$authSource->doAuth($state);
	}
} catch (Exception $e) {
    $e->logError();
	$error = $e->getMessage();
}

$config = SimpleSAML_Configuration::getInstance();
$t = new SimpleSAML_XHTML_Template($config, 'authgoogle:consumer.php', 'openid');
if (!empty($error)) {
    $t->data['error'] = $error;
}
$t->data['AuthState'] = $authState;
$t->show();
