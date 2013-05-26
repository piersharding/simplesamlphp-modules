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
 * Class which implements the authigovt session store logic.
 * This simply stashes key values in the underlying user session that
 * can be pulled back at later steps in the authentication process
 *
 */
class sspmod_authigovt_SessionStore {

	/**
	 * Retrieve a key from the session store.
	 *
	 * @param string $key  The key we should retrieve.
	 * @return mixed  The value stored with the given key, or NULL if the key isn't found.
	 */
	public function get($key) {
		assert('is_string($key)');

		$session = SimpleSAML_Session::getInstance();
		return $session->getData('authigovt.session', $key);
	}


	/**
	 * Save a value to the session store under the given key.
	 *
	 * @param string $key  The key we should save.
	 * @param mixed NULL $value  The value we should save.
	 */
	public function set($key, $value) {
		assert('is_string($key)');

		$session = SimpleSAML_Session::getInstance();
		$session->setData('authigovt.session', $key, $value);
	}


	/**
	 * Delete a key from the session store.
	 *
	 * @param string $key  The key we should delete.
	 */
	public function del($key) {
		assert('is_string($key)');

		$session = SimpleSAML_Session::getInstance();
		$session->deleteData('authigovt.session', $key);
	}

}
