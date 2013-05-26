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
 * Landing page to trigger Single Logon Service return leg for user coming from
 * AVS
 */

$config = SimpleSAML_Configuration::getInstance();
$moduleConfig = SimpleSAML_Configuration::getConfig('module_igovt.php');
// WS endpoint
$destination = $moduleConfig->getValue('iCMS.RSTIssue.Endpoint');
// target partner for opaque token exchange
$partner = $moduleConfig->getValue('iCMS.SLS.Partner');

// start the overall timer
$overall = new sspmod_authigovt_Timer('saml20-idp-igovt-SLS', $destination, $partner);

$session = SimpleSAML_Session::getInstance();

SimpleSAML_Logger::info('SAML2.0 - SP.initSLS: Going to jump back to RealMe');

// check that we are authenticated
$auth = new SimpleSAML_Auth_Simple($moduleConfig->getValue('authcheck'));
if (!$auth->isAuthenticated()) {
    /* Send them back to the Dashboard login page */
    // throw new SimpleSAML_Error_Error('User is not logged in to iGovt');
    $overall->finish('LOGGEDOUT');
    SimpleSAML_Utilities::redirect($moduleConfig->getValue('RealMe.Landing.Page'));
}

// get back attributes
$attributes = $session->getAttributes();

// Call the iCMS to get the Opaque Token
// SP that contains the iGovt config
$delegateSP = $moduleConfig->getValue('delegate-sp');

// temp hack for grabbing the iGovt login token to pass on
// This whole process assumes that the user has been logged in via the iGovt login process within the current
// session and that the related token has not timed out - expires 60 minutes
$assertion = $attributes['logon_attributes_token'][0];
try {
    $timeit = new sspmod_authigovt_Timer('saml20-idp-AQ-RST-SLS', $destination, $partner, $overall->id);
    $rstRequest = sspmod_authigovt_Utils::makeRSTRequestSeamless($delegateSP, $partner, $destination, $assertion);
    $timeit->finish('OK');
}
catch (Exception $e) {
    // cannot get the Opaque Token - set a message
    $overall->finish('ERROR');
    // throw new SimpleSAML_Error_Error('Cannot get Opaque Token for Seamless login');
    SimpleSAML_Utilities::redirect($moduleConfig->getValue('iCMS.SLS.Redirect'));
}

$iCMSEndpoint = $moduleConfig->getValue('iCMS.SLS.Endpoint');
$relayState = $moduleConfig->getValue('iCMS.SLS.RelayState', NULL);

$post = array('OT' => $rstRequest);
if (!empty($relayState)) {
    $post['RelayState'] = $relayState;
}

// force logout before redirect
$session->doLogout();

$overall->finish('OK');

// forward the user to the SLS with the token
SimpleSAML_Utilities::postRedirect($iCMSEndpoint, $post);

