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

/*
 * Disable strict error reporting, since the OpenID library
 * used is PHP4-compatible, and not PHP5 strict-standards compatible.
 */
SimpleSAML_Utilities::maskErrors(E_STRICT);

/**
 * Authentication module which acts as an iGovt SP
 *
 */
class sspmod_authigovt_Auth_Source_iGovt extends SimpleSAML_Auth_Source {

    /**
     * Static openid target to use.
     *
     * @var string|NULL
     */
    private $target;

    /**
     * what is the sp that we delegate to
     */
    private $delegatesp;

    /**
     * what is the authid of the login mechanism
     */
    private $loginauthid;

    /**
     * Host and port to connect to
     */
    private $host;
    private $port;

    /**
     * Ldap Protocol
     */
    private $protocol;

    /**
     * Bind DN and password
     */
    private $binddn;
    private $password;

    /**
     * Base DN to search LDAP
     */
    private $basedn;

    /**
     * Search filter
     */
    private $searchfilter;

    /**
     * LDAP handler
     */
    private $ds;

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

		$this->delegatesp = $cfgParse->getString('delegate-sp', false);


		foreach (array('host', 'port', 'binddn', 'password', 'basedn', 'searchfilter') as $id) {
		    if (!array_key_exists($id, $config)) {
		        throw new Exception('authigovt:iGovt - Missing required option \'' . $id . '\'.');
		    }
		    if ($id != 'port' && !is_string($config[$id])) {
		        throw new Exception('authigovt:iGovt - \'' . $id . '\' is supposed to be a string.');
		    }
		}

		if(!array_key_exists('protocol', $config)) {
		    $this->protocol = 3;
		}
		else {
		    $this->protocol = (integer)$config['protocol'];
		}

		$this->host = $config['host'];
		$this->port = $config['port'];
		$this->binddn = $config['binddn'];
		$this->password = $config['password'];
		$this->basedn = $config['basedn'];
		$this->searchfilter = $config['searchfilter'];
	}

	/**
	 * Connects and binds to the configured LDAP server. Stores LDAP
	 * handler in $this->ds
	 */
	public function bindLdap() {
	    // Bind to LDAP
	    $ds = ldap_connect($this->host, $this->port);
	    ldap_set_option($ds, LDAP_OPT_PROTOCOL_VERSION, $this->protocol);
	    if (is_null($ds)) {
	        throw new Exception('authigovt:iGovt - Cannot connect to LDAP');
	    }

	    if (ldap_bind($ds, $this->binddn,
	                    $this->password) !== TRUE) {
	        throw new Exception('authigovt:iGovt - Cannot bind to LDAP');
	    }

	    $this->ds = $ds;
	    return $ds;
	}


	/**
	 * searches for a given user
	 */
	public function searchLdap($userid) {
        // Prepare filter
        $filter = preg_replace('/:uidfield/', $userid,
                        $this->searchfilter);

        $res = @ldap_search($this->ds, $this->basedn, $filter, array('dn'));

        if ($res === FALSE) {
            // Problem with LDAP search
            throw new Exception('authigovt:iGovt - LDAP Error when trying to fetch user attributes');
        }
        $info = @ldap_get_entries($this->ds, $res);
        return $info;
	}

    /**
     * Initiate authentication. Redirecting the user to the consumer endpoint
     * with a state Auth ID.
     *
     * @param array &$state  Information about the current authentication.
     */
    public function authenticate(&$state) {
        assert('is_array($state)');

		$state['authigovt:AuthId'] = $this->authId;
		$state[sspmod_core_Auth_UserPassBase::AUTHID] = $this->loginauthid;

        $as = new SimpleSAML_Auth_Simple($this->delegatesp);
        if (!$as->isAuthenticated()) {
            $id = SimpleSAML_Auth_State::saveState($state, 'authigovt:state');
            $session = new sspmod_authigovt_SessionStore();
            $session->set('AuthState', $id);
            $session->set('ReturnTo', SimpleSAML_Utilities::selfURL());
	        $params = array(
	            'ReturnTo' => SimpleSAML_Module::getModuleURL('authigovt/callback.php'),
        	);
        	$as->login($params);
        }

        // shouldn't be here ...
        SimpleSAML_Utilities::redirect(SimpleSAML_Module::getModuleURL('authigovt/callback.php'));
	}


	/**
	 * Complete the authentication by locally connecting the user in the LDAP directory
     * If they don't match up then they must go through the login linking process
     * If they do match up, then pull in the users LDAP attributes
	 *
	 * @param array &$state  Information about the current authentication.
	 */
	public function postAuth(&$state) {
	    assert('is_array($state)');

	    $state['authigovt:AuthId'] = $this->authId;
	    $state[sspmod_core_Auth_UserPassBase::AUTHID] = $this->loginauthid;

	    $as = new SimpleSAML_Auth_Simple($this->delegatesp);
	    if (!$as->isAuthenticated()) {
	        throw new SimpleSAML_Error_BadRequest('User must be logged in for postAuth.');
	    }
	    $attributes = $as->getAttributes();

	    // check for corresponding internal account
	    SimpleSAML_Logger::debug('iGovt returned Attributes: '. implode(", ",array_keys($attributes)));

	    // Bind to LDAP
	    $this->bindLdap();

	    $userid = $attributes['nameid'][0];

	    // Search
	    $info = $this->searchLdap($userid);
	    if (empty($info) || $info['count'] != 1) {
	        $session = new sspmod_authigovt_SessionStore();
	        $id = $session->get('AuthState');
	        $session->set('nameid', $userid);
	        $session->set('AUTHID', $this->loginauthid);
	        $url = SimpleSAML_Module::getModuleURL('authigovt/loginuserpass.php');
	        SimpleSAML_Utilities::redirect($url, array('AuthState' => $id));
	        die();
	    }

	    // resurect the state and continue
	    $session = new sspmod_authigovt_SessionStore();
	    $id = $session->get('AuthState');
	    if (!empty($id)) {
	        $session->del('AuthState');
	        $state = SimpleSAML_Auth_State::loadState($id, 'authigovt:state');
	    }
	    $state['Attributes'] = $attributes;
	    SimpleSAML_Logger::debug('going to complete: '.var_export($state['SimpleSAML_Auth_Default.Return'], true));
	    SimpleSAML_Auth_Source::completeAuth($state);
	}


	/**
	 * Log out from this authentication source, and the iGovt delegated source
	 *
	 * @param array &$state  Information about the current logout operation.
	 */
	public function logout(&$state) {
	    assert('is_array($state)');

	    $session = SimpleSAML_Session::getInstance();
        $session->doLogout($this->authId);
        $session->doLogout($this->delegatesp);
        return;
	}
}
