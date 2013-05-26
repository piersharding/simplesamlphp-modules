<?php

/**
 * sessionJSON: SimpleSAMLphp JSON encoded session store on Memcache
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

class sspmod_sessionJSON_Store_Store extends SimpleSAML_Store {

	/**
	 * Initialize the memcache datastore.
	 */
	public function __construct() {
	}


	/**
	 * Retrieve a value from the datastore.
	 *
	 * @param string $type  The datatype.
	 * @param string $key  The key.
	 * @return mixed|NULL  The value.
	 */
	public function get($type, $key) {
		assert('is_string($type)');
		assert('is_string($key)');

		$res = sspmod_sessionJSON_Store_Memcache::get('simpleSAMLphp.' . $type . '.' . $key);
		if ($type == 'session') {
			$jsonkey = 'simpleSAMLphp.' . $type . '.json.' . $key;
			$json = sspmod_sessionJSON_Store_Memcache::jsonget($jsonkey);
			// check that the cache is correct for json component
			if (empty($res) || $json != $res->getAttributes()) {
				$attrs = (empty($res) ? array() : $res->getAttributes());
				$attrs = (empty($attrs) ? array() : $attrs);
				$config = SimpleSAML_Configuration::getInstance();
				$sessionDuration = $config->getInteger('session.duration', 8*60*60);
				$expire = time() + $sessionDuration;
				sspmod_sessionJSON_Store_Memcache::jsonset($jsonkey, $attrs, $expire);
			}
		}
		return $res;
	}


	/**
	 * Save a value to the datastore.
	 *
	 * @param string $type  The datatype.
	 * @param string $key  The key.
	 * @param mixed $value  The value.
	 * @param int|NULL $expire  The expiration time (unix timestamp), or NULL if it never expires.
	 */
	public function set($type, $key, $value, $expire = NULL) {
		assert('is_string($type)');
		assert('is_string($key)');
		assert('is_null($expire) || (is_int($expire) && $expire > 2592000)');

		if ($expire === NULL) {
			$expire = 0;
		}

		if ($type == 'session') {
			// reset the replay indicators
			self::set('replay', $key, array());
			// store the JSON copy
			if (is_object($value) && get_class($value) == 'SimpleSAML_Session') {
				$attrs = $value->getAttributes();
				$attrs = (empty($attrs) ? array() : $attrs);
				// SimpleSAML_Logger::debug('json_encoded: '.var_export(json_encode($attrs), true));
				$jsonkey = 'simpleSAMLphp.' . $type . '.json.' . $key;
				// key will look like:
				// get simpleSAMLphp.session.json.7d944723c1224ade5403199794eb8a20
				sspmod_sessionJSON_Store_Memcache::jsonset($jsonkey, $attrs, $expire);
			}
		}
		sspmod_sessionJSON_Store_Memcache::set('simpleSAMLphp.' . $type . '.' . $key, $value, $expire);
	}


	/**
	 * Delete a value from the datastore.
	 *
	 * @param string $type  The datatype.
	 * @param string $key  The key.
	 */
	public function delete($type, $key) {
		assert('is_string($type)');
		assert('is_string($key)');

		if ($type == 'session') {
			$jsonkey = 'simpleSAMLphp.' . $type . '.json.' . $key;
			sspmod_sessionJSON_Store_Memcache::delete($jsonkey);
		}
		sspmod_sessionJSON_Store_Memcache::delete('simpleSAMLphp.' . $type . '.' . $key);
	}

}
