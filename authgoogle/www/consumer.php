<?php

$config = SimpleSAML_Configuration::getInstance();

/* Find the authentication state. */
if (!array_key_exists('AuthState', $_REQUEST)) {
	throw new SimpleSAML_Error_BadRequest('Missing mandatory parameter: AuthState');
}
$state = SimpleSAML_Auth_State::loadState($_REQUEST['AuthState'], 'authgoogle:state');
$authState = $_REQUEST['AuthState'];
$authSource = SimpleSAML_Auth_Source::getById($state['authgoogle:AuthId']);
if ($authSource === NULL) {
	throw new SimpleSAML_Error_BadRequest('Invalid AuthId \'' . $state['authgoogle:AuthId'] . '\' - not found.');
}

try {
	if (array_key_exists('returned', $_GET)) {
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
