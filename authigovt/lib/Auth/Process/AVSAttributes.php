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
 * Demo call to AVS IAP over SAML AttributeQuery
 *
 */
class sspmod_authigovt_Auth_Process_AVSAttributes extends SimpleSAML_Auth_ProcessingFilter {

	/**
	 * AQS URL - Destination and endpoint
	 */
	private $aqsurl = null;

	/**
	 * Source Id - local authentication source to derive local SP profile from
	 */
	private $sourceid = null;

	/**
	 * Auth Id - auth id of the authigovt:iGovt instance in authsources
	 */
	private $authid = null;

	/**
	 * Endpoint that should be active
	 */
	private $endpoint = null;

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
	 * Initialize this filter, parse configuration
	 *
	 * @param array $config  Configuration information about this filter.
	 * @param mixed $reserved  For future use.
	 */
	public function __construct($config, $reserved) {
		parent::__construct($config, $reserved);

		assert('is_array($config)');
		if (empty($config['aqsurl']) || !is_string($config['aqsurl'])) {
		    throw new Exception('authigovt:AVSAttributes: missing aqsurl: ' . var_export($config, TRUE));
		}
		$this->aqsurl = $config['aqsurl'];
		if (empty($config['sourceid']) || !is_string($config['sourceid'])) {
		    throw new Exception('authigovt:AVSAttributes: missing sourceid: ' . var_export($config, TRUE));
		}
		$this->sourceid = $config['sourceid'];
		if (empty($config['authid']) || !is_string($config['authid'])) {
		    throw new Exception('authigovt:AVSAttributes: missing authid: ' . var_export($config, TRUE));
		}
		$this->authid = $config['authid'];
		if (empty($config['endpoint']) || !is_string($config['endpoint'])) {
		    throw new Exception('authigovt:AVSAttributes: missing endpoint: ' . var_export($config, TRUE));
		}
		$this->endpoint = $config['endpoint'];


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
		$this->saveattr = $config['saveattr'];
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
     * XPath query helper
     *
     */
	private static function xPathQ($node, $query) {
        if ($node instanceof DOMDocument) {
            $doc = $node;
        } else {
            $doc = $node->ownerDocument;
        }
        $xpCache = new DOMXPath($doc);
        $xpCache->registerNamespace('xnal', 'urn:oasis:names:tc:ciq:xnal:3');
        $xpCache->registerNamespace('a', 'urn:oasis:names:tc:ciq:xal:3');
        $xpCache->registerNamespace('p', 'urn:oasis:names:tc:ciq:xpil:3');
        $results = $xpCache->query($query, $node);
        $ret = array();
        for ($i = 0; $i < $results->length; $i++) {
            $ret[$i] = $results->item($i);
        }
        return $ret;
	}

    /**
     * CIQ v3 Address parser helper
     *
     */
	private static function parseAddr($xml) {
        $dom = new DOMDocument();
    	$dom->loadXML($xml);

        $city = self::xPathQ($dom->firstChild, "/p:Party/a:Addresses/a:Address/a:Locality/a:NameElement[@a:NameType='NZTownCity']");
        $suburb = self::xPathQ($dom->firstChild, "/p:Party/a:Addresses/a:Address/a:Locality/a:NameElement[@a:NameType='NZSubburb']");
        $thoroughfare = self::xPathQ($dom->firstChild, "/p:Party/a:Addresses/a:Address/a:Thoroughfare/a:NameElement[@a:NameType='NZNumberStreet']");
        $unit = self::xPathQ($dom->firstChild, "/p:Party/a:Addresses/a:Address/a:Premises/a:NameElement[@a:NameType='NZUnit']");
        $postcode = self::xPathQ($dom->firstChild, "/p:Party/a:Addresses/a:Address/a:PostCode/a:Identifier[@Type='NZPostCode']");
    	$addrvalues = array();
    	foreach (array($unit, $thoroughfare, $suburb, $city, $postcode) as $component) {
    		if (!empty($component)) {
    			foreach ($component as $el) {
                    if (empty($el->nodeValue)) {
                        continue;
                    }
    				$addrvalues[]= $el->nodeValue;
    			}
    		}
    	}
    	return implode(", ", $addrvalues);
      }


	/**
	 * Apply filter to perform the Attribbute Query calls to the AVS side
     * First call is a status check
     * second call retrieves the CIQv3 Address
     * values are stashed in LDAP directory for testing purposes
	 *
	 * @param array &$request  The current request
	 */
	public function process(&$request) {
		assert('is_array($request)');
		assert('array_key_exists("Attributes", $request)');
        SimpleSAML_Logger::debug("process request parameter: ".var_export(array_keys($request), true));
		$currentURL = SimpleSAML_Utilities::selfURLNoQuery();
		if ($currentURL != $this->endpoint) {
			SimpleSAML_Logger::debug('allready been here - attributes: '.var_export($request['Attributes'], true));
			return;
		}

		if (empty($request['Attributes']['nameid'])) {
		    return;
		}
		$attributes =& $request['Attributes'];

        // Call the iCMS to get the Opaque Token
        $moduleConfig = SimpleSAML_Configuration::getConfig('module_igovt.php');
        // WS endpoint
        $destination = $moduleConfig->getValue('iCMS.RSTIssue.Endpoint');
        // target partner for opaque token exchange
        $partner = $moduleConfig->getValue('iCMS.AQPartner');
        // target partner for IAP
        $iappartner = $moduleConfig->getValue('IAP.AQPartner');
        // SP that contains the iGovt config
        $delegateSP = $moduleConfig->getValue('delegate-sp');

		// temp hack for grabbing the iGovt login token to pass on
		$assertion = $attributes['logon_attributes_token'][0];
        try {
		  $rstRequest = sspmod_authigovt_Utils::makeRSTRequest($delegateSP, $partner, $destination, $assertion);
        }
        catch (Exception $e) {
            // cannot get the Opaque Token - set a message
            throw new SimpleSAML_Error_Error('Cannot get Opaque Token');
        }

        // Login required
        $session = SimpleSAML_Session::getInstance();
        $aqc = new sspmod_authigovt_AQC();

        $data = array();
        $aqattributes = NULL;

        $nameId = array(
                        'Format' => 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
                        'Value' => $rstRequest,
                        'NameQualifier' => NULL,
                        'SPNameQualifier' => NULL,
        );

        try {
            // do status check
            $reqAttributes = array('urn:nzl:govt:ict:stds:authn:attribute:igovt:AVS:Identity:Status' => array());
            $response = $aqc->sendQuery($this->aqsurl, $this->sourceid, $iappartner, $nameId, $reqAttributes, 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic');
            $aqattributes = $response->getAttributes();
            SimpleSAML_Logger::debug('attributes from AQ status check: '.var_export($aqattributes, true));
            if (!array_key_exists('urn:nzl:govt:ict:stds:authn:attribute:igovt:AVS:Identity:Status', $aqattributes) ||
                $aqattributes['urn:nzl:govt:ict:stds:authn:attribute:igovt:AVS:Identity:Status'][0] != 'VER') {
                // force the logout so they try again
                $this->logout();
                throw new Exception(SAML2_Const::STATUS_RESPONDER, 'urn:oasis:names:tc:SAML:2.0:status:RequestDenied', 'User has not been verified at AVS');
            }

            // now to the address call
            $reqAttributes = array('urn:nzl:govt:ict:stds:authn:safeb64:attribute:NZPost:AVS:Address' => array());
            $aqattributes = NULL;
            $response = $aqc->sendQuery($this->aqsurl, $this->sourceid, $iappartner, $nameId, $reqAttributes, 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic');
            $aqattributes = $response->getAttributes();

            SimpleSAML_Logger::debug('attributes from AQ: '.var_export($aqattributes, true));
            foreach ($aqattributes as $k => $v) {
                $attributes[$k] = $v;
            }
            $data = str_replace(array('-','_'), array('+','/'), $aqattributes['urn:nzl:govt:ict:stds:authn:safeb64:attribute:NZPost:AVS:Address'][0]);
            $addr = base64_decode($data);
            SimpleSAML_Logger::debug('Raw address: '.var_export($addr, true));
            $attributes['address'] = array(self::parseAddr($addr));
            SimpleSAML_Logger::debug('combined attributes: '.var_export($attributes, true));
        }
        catch (Exception $e) {
            // stash the error message for the login into LDAP
            $attributes['address'] = array($e->getMessage());
        }

        // now update the directory with the error or the new address values
	    try {
		    // Bind to LDAP
		    $ds = $this->bindLdap();

		    // Search
		    $userid = $attributes['nameid'][0];
		    $info = $this->searchLdap($userid);

		    // Save AVS data in LDAP
		    if (!empty($info) && $info['count'] == 1) {
	    	    // update user with AVS data
	    	    $dn = $info[0]['dn'];

	    	    // stick the AVS data on the LDAP user
			    $mod_user = array($this->saveattr => $attributes['address']);
			    if(!ldap_modify($ds, $dn, $mod_user)) {
			        SimpleSAML_Logger::debug("user update failed: ".var_export($mod_user, true));
			    }
		    }
	    }
	    catch (Exception $e) {
            SimpleSAML_Logger::debug('BAD Exception on AQ: '.var_export(get_class($e), true).' '.$e->getMessage());
            SimpleSAML_Logger::debug('Forced logout and sending them back: '.var_export($request['saml:RelayState'], true));
            $this->logout();
            // send them back where they came from
            SimpleSAML_Utilities::redirect($request['saml:RelayState']);
        }
    }

    /**
     * logout callback
     * This will force the user to be logged out of all associated authentcation sources
     * with the users session
     *
     */
    private function logout() {
        // force the logout so they try again
        $authSource = SimpleSAML_Auth_Source::getById($this->authid);
        $dummyState = array();
        $authSource->logout($dummyState);
        $session = SimpleSAML_Session::getInstance();
        $session->doLogout();
    }
}

