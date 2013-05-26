<?php

/**
 * sessionJSON: SimpleSAMLphp session token exchanger
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
 * @subpackage sessionJSON
 * @author     Catalyst IT Ltd
 * @author     Piers Harding
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL
 * @copyright  (C) 2012-2013 Catalyst IT Ltd http://catalyst.net.nz
 *
 */

$moduleConfig = SimpleSAML_Configuration::getConfig('module_sessionJSON.php');
$issuer = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] == 'on' ? 'https' : 'http').'//'.$_SERVER['SERVER_NAME'].$_SERVER['SCRIPT_NAME'];
$private_api_key = null;
$id = null;
$loggedin = false;

try {
    // Session attributes to return
    $attrs = $moduleConfig->getArray('session.attributes', array());
    if (empty($attrs)) {
        throw new Exception('module not configured correctly (attributes)', 500);
    }

    // API token
    $api_keys = $moduleConfig->getValue('API.Token', array());
    if (empty($api_keys)) {
        throw new Exception('module not configured correctly (keys)', 500);
    }


    // check that the client is within an allowed address range
    $subnets = $moduleConfig->getArray('Restricted.Subnets', array());
    if (!checkMask($subnets)) {
        throw new Exception("Content restricted (Forbidden)", 403);
    }

    // check that the private_api_key is correct
    if (array_key_exists('private_api_key', $_REQUEST)) {
        $private_api_key = $_REQUEST['private_api_key'];
    }
    else {
        throw new Exception('API key not provided (Unauthorized)', 401);
    }
    if (!isset($api_keys[$private_api_key])) {
        throw new Exception('API key invalid (Unauthorized)', 401);
    }

    // check the id supplied
    if (array_key_exists('id', $_REQUEST)) {
        $id = $_REQUEST['id'];
    }
    else {
        throw new Exception("Id not supplied (Bad request)", 400);
    }

    // pull the associated session attributes and return as a JSON object
    $store = new sspmod_sessionJSON_Store_Store();
    $session = $store->get('session', $id);
    if (empty($session)) {
        throw new Exception("Not Found", 404);
    }

    // do we allow replay?
    $no_replay = $moduleConfig->getBoolean('No.Replay', true);

    $attributes = $session->getAttributes();

    // if no replay is activated, then test whether the session has been accessed for the current private key
    $replay = array();
    if ($no_replay) {
        $replay = $store->get('replay', $id);
        // var_dump($replay);
        if (empty($replay)) {
            $replay = array();
        }
        if (isset($replay[$private_api_key]) &&
            $replay[$private_api_key]) {
            throw new Exception("Content unavailable (Forbidden)", 403);
        }
    }

    $return = array();
    foreach ($attrs as $attr) {
        if (isset($attributes[$attr])) {
            $return[$attr] = $attributes[$attr];
        }
    }
    $return['remaining_time'] = array($session->remainingTime());
    $return['is_authenticated'] = array($session->isAuthenticated());
    if ($return['remaining_time'][0] < 1 || $return['is_authenticated'][0] == false) {
        $return['remaining_time'][0] = -1;
        $return['is_authenticated'][0] = false;
    }
    else {
        $loggedin = true;
    }
    $return = json_encode($return);

    // set the no replay flag
    if ($no_replay) {
        $replay[$private_api_key] = 1;
        $store->set('replay', $id, $replay);
    }

    // return the results
    SimpleSAML_Logger::debug("session data returning(".$id."): ".$return);
    SimpleSAML_Logger::stats('saml20-idp-session-REQ ' . $private_api_key . ' ' . $id . ' ' . $issuer . ' OK:'.($loggedin ? 'LOGGEDIN' : 'LOGGEDOUT'));
    header('Content-Type: application/json');
    header('Content-Length: '.strlen($return));
    print $return;
    exit(0);
}
catch (Exception $e) {
    $msg = $e->getMessage();
    $code = $e->getCode();
    SimpleSAML_Logger::stats('saml20-idp-session-REQ ' . $private_api_key . ' ' . $id . ' ' . $issuer . ' ERR:'.$code.':'.$msg);
    header('HTTP/1.0 '.$code.' '.$msg);
    echo $code.' - '.$msg."\n";
}


/**
 * checkMask() looks up the subnet config option and verifies
 * that the client is within that range.
 *
 * Will return TRUE if no subnet option is configured.
 *
 * @param array subnets - allowed subnets
 * @return boolean
 */
 function checkMask($subnets) {
    // No subnet means all clients are accepted.
    if (empty($subnets))
        return TRUE;
    $ip = $_SERVER['REMOTE_ADDR'];
    foreach ($subnets as $cidr) {
        $ret = SimpleSAML_Utilities::ipCIDRcheck($cidr);
        if ($ret) {
            SimpleSAML_Logger::debug('resolver: Client "'.$ip.'" matched subnet.');
            return TRUE;
        }
    }
    SimpleSAML_Logger::debug('resolver: Client "'.$ip.'" did not match subnet.');
    return FALSE;
}
