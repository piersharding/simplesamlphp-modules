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
 * Landing page for return from iGovt signin - continue authentication process
 */

// resurect the state and continue
$session = new sspmod_authigovt_SessionStore();
$id = $session->get('AuthState');
if (empty($id)) {
    throw new SimpleSAML_Error_BadRequest('State not found.');
}

$state = SimpleSAML_Auth_State::loadState($id, 'authigovt:state');
$sourceId = $state['authigovt:AuthId'];
$authSource = SimpleSAML_Auth_Source::getById($sourceId);
if ($authSource === NULL) {
    throw new SimpleSAML_Error_BadRequest('Invalid AuthId \'' . $sourceId . '\' - not found.');
}

try {
    $authSource->postAuth($state);
    /* postAuth() should never return. */
    assert('FALSE');
} catch (SimpleSAML_Error_Exception $e) {
    SimpleSAML_Auth_State::throwException($state, $e);
} catch (Exception $e) {
    SimpleSAML_Auth_State::throwException($state, new SimpleSAML_Error_AuthSource($sourceId, 'Error on iGovt callback endpoint.', $e));
}
die();
