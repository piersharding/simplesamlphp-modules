<?php

/*
 * Disable strict error reporting, since the OpenID library
 * used is PHP4-compatible, and not PHP5 strict-standards compatible.
 */
SimpleSAML_Utilities::maskErrors(E_STRICT);

/* Add the OpenIDConnect library to the search path. */
set_include_path(get_include_path() . PATH_SEPARATOR . dirname(dirname(dirname(dirname(__FILE__)))) . '/extlib');
require_once('OpenIDConnectClient.php5');

// require_once('Auth/OpenID/AX.php');
// require_once('Auth/OpenID/SReg.php');
// require_once('Auth/OpenID/Server.php');
// require_once('Auth/OpenID/ServerRequest.php');

/**
 * Authentication module which acts as an OpenID Consumer for Google OpenIdConnect
 *
 * @author Piers Harding, piers@catalyst.net.nz
 * @package simpleSAMLphp
 * @version $Id$
 */
class sspmod_authgoogle_Auth_Source_OpenIDConsumer extends SimpleSAML_Auth_Source {

    /**
     * Static openid target to use.
     *
     * @var string|NULL
     */
    private $target;

    /**
     * Do we force Google to Login again
     */
    private $forceLogin;

    /**
     * do we specify the Google domain
     */
    private $googleDomain;


	/**
	 * Constructor for this authentication source.
	 *
	 * @param array $info  Information about this authentication source.
	 * @param array $config  Configuration.
	 */
	public function __construct($info, $config) {

		/* Call the parent constructor first, as required by the interface. */
		parent::__construct($info, $config);

		$cfgParse = SimpleSAML_Configuration::loadFromArray($config,
			'Authentication source ' . var_export($this->authId, TRUE));

		$this->forceLogin = $cfgParse->getBoolean('forcelogin', false);
		// $this->googleDomain = $cfgParse->getString('googleDomain', false);
        $this->clientid = $cfgParse->getString('clientid', false);
        $this->secret = $cfgParse->getString('secret', false);
	}


    /**
     * Initiate authentication. Redirecting the user to the consumer endpoint
     * with a state Auth ID.
     *
     * @param array &$state  Information about the current authentication.
     */
    public function authenticate(&$state) {
        assert('is_array($state)');

		$state['authgoogle:AuthId'] = $this->authId;

		if ($this->target !== NULL) {
			$this->doAuth($state);
		}

		$id = SimpleSAML_Auth_State::saveState($state, 'authgoogle:state');

		$url = SimpleSAML_Module::getModuleURL('authgoogle/consumer.php');
		SimpleSAML_Utilities::redirect($url, array('AuthState' => $id));
	}

    /**
     * Retrieve the URL we should return to after successful authentication.
     *
     * @return string  The URL we should return to after successful authentication.
     */
    private function getReturnTo($stateId) {
        assert('is_string($stateId)');

        return SimpleSAML_Module::getModuleURL('authgoogle/consumer.php', array(
            'returned' => 1,
            'AuthState' => $stateId,
        ));
    }

    /**
     * Send an authentication request to the OpenID provider.
     *
     * @param array &$state  The state array.
     * @param string $openid  The OpenID we should try to authenticate with.
     */
    public function doAuth(array &$state) {

        $stateId = SimpleSAML_Auth_State::saveState($state, 'authgoogle:state');

        try {
            $oidc = new OpenIDConnectClient('https://accounts.google.com',
                                            $this->clientid,
                                            $this->secret);
            $oidc->addScope(array("openid", "email", "profile"));

            if ($this->forceLogin) {
                $oidc->addAuthParam(array('prompt' => 'login'));
            }

            // $oidc->setRedirectURL($this->getReturnTo($stateId));
            $_SESSION['openid_connect_AuthState'] = $stateId;

            $oidc->authenticate();
            // Only the guaranteed ones
            $data = array('firstname' => $oidc->requestUserInfo('given_name'),
                           'lastname' => $oidc->requestUserInfo('family_name'),
                           'name' => $oidc->requestUserInfo('name'),
                           'email' => $oidc->requestUserInfo('email'),
                           'openid' => $oidc->requestUserInfo('sub'),
                           );
        }
        catch(OpenIDConnectClientException $e) {
            // major failure
            throw new Exception("Google OpenIDConnect failure: ".$e->getMessage());
        }
        catch(Exception $e) {
            // major failure
            throw new Exception("Google OpenIDConnect unknown failure: ".$e->getMessage());
        }

        if (empty($data)) {
            throw new Exception("Google OpenIDConnect no login data");
        }

        return $data;
    }


    /**
     * Process an authentication response.
     *
     * @param array &$state  The state array.
     */
    public function postAuth(array &$state) {

        $data = $this->doAuth($state);
        SimpleSAML_Logger::debug('OpenID got data: '. implode(", ",array_keys($data)));

        // $return_to = SimpleSAML_Utilities::selfURL();

        // This means the authentication succeeded; extract the
        // identity URL and Simple Registration data (if it was
        // returned).
        $attributes = array();
        foreach ($data AS $key => $value) {
            $attributes[$key] = array($value);
            SimpleSAML_Logger::warning('attribute in response: '.$key.' - '.var_export($value, TRUE));
        }
        SimpleSAML_Logger::debug('OpenID Returned Attributes: '. implode(", ",array_keys($attributes)));

        $state['Attributes'] = $attributes;
        SimpleSAML_Auth_Source::completeAuth($state);
    }
}
