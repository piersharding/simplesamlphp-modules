<?php

/**
 * Example authentication source - username & password.
 *
 * This class is an example authentication source which stores all username/passwords in an array,
 * and authenticates users against this array.
 *
 * @author Piers Harding, Catalyst IT
 * @package simpleSAMLphp
 * @version $Id$
 */
class sspmod_moodleauth_Auth_Source_UserPass extends sspmod_core_Auth_UserPassBase {


	/**
	 * The root of the Moodle instance to integrate with.
	 */
	private $moodleroot;

	/**
	 * The config for moodle.
	 */
	private $moodleconfig;

	/**
	 * The DSN we should connect to.
	 */
	private $dsn;

	/**
	 * Constructor for this authentication source.
	 *
	 * @param array $info  Information about this authentication source.
	 * @param array $config  Configuration.
	 */
	public function __construct($info, $config) {
		assert('is_array($info)');
		assert('is_array($config)');

		/* Call the parent constructor first, as required by the interface. */
		parent::__construct($info, $config);

		/* Make sure that all required parameters are present. */
		foreach (array('moodleroot') as $param) {
			if (!array_key_exists($param, $config)) {
				throw new Exception('Missing required attribute \'' . $param .
					'\' for authentication source ' . $this->authId);
			}

			if (!is_string($config[$param])) {
				throw new Exception('Expected parameter \'' . $param .
					'\' for authentication source ' . $this->authId .
					' to be a string. Instead it was: ' .
					var_export($config[$param], TRUE));
			}
		}

		$this->moodleroot = $config['moodleroot'];

		// Catch anything that goes wrong in config.php
		ob_start();
		$code = explode("\n", file_get_contents($this->moodleroot . '/config.php'));
		$code = implode("\n", preg_grep('/(\<\?)|(\?\>)|(require)/', $code, PREG_GREP_INVERT));
		eval($code);
	    $errors = trim(ob_get_contents());
		ob_end_clean();

		// $bcrypt_cost = (isset($CFG->bcrypt_cost) ? $CFG->bcrypt_cost : NULL);
		// // bcrypt_cost is the cost parameter passed as part of the bcrypt hash
		// // See http://php.net/manual/en/function.crypt.php
		// // The value is a 2 digit number in the range of 04-31
		// if (!$bcrypt_cost || !is_int($bcrypt_cost) || $bcrypt_cost < 4 || $bcrypt_cost > 31) {
		//     $bcrypt_cost = 12;
		// }
		// $CFG->bcrypt_cost = sprintf('%02d', $bcrypt_cost);

		// // passwordsaltmain - ensure it exists
		// $CFG->passwordsaltmain = (isset($CFG->passwordsaltmain) ? $CFG->passwordsaltmain : '');

		$this->moodleconfig = $CFG;

		SimpleSAML_Logger::info('sspmod_moodleauth_Auth_Source_UserPass:' . $this->authId . ': config: ' .
			var_export($this->moodleconfig, true));

		if (preg_match('/postgres/', $CFG->dbtype)) {
			$dbtype = 'pgsql';
		}
		else if (preg_match('/mysql/', $CFG->dbtype)) {
			$dbtype = 'mysql';
		}
		else {
			$dbtype = $this->dbtype;
		}
		$this->dsn = $dbtype.':host='.$CFG->dbhost.(!empty($CFG->dbport) ? ';port=' : '').';dbname='.$CFG->dbname;
		// 'pgsql:host=localhost;port=5432;dbname=moodledev'

		SimpleSAML_Logger::info('sspmod_moodleauth_Auth_Source_UserPass:' . $this->authId . ': dsn: ' .
			$this->dsn);
	}



	/**
	 * Create a database connection.
	 *
	 * @return PDO  The database connection.
	 */
	private function connect() {
		try {
			$db = new PDO($this->dsn, $this->moodleconfig->dbuser, $this->moodleconfig->dbpass);
		} catch (PDOException $e) {
			throw new Exception('moodleauth:' . $this->authId . ': - Failed to connect to \'' .
				$this->dsn . '\': '. $e->getMessage());
		}

		$db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);


		$driver = explode(':', $this->dsn, 2);
		$driver = strtolower($driver[0]);

		/* Driver specific initialization. */
		switch ($driver) {
		case 'mysql':
			/* Use UTF-8. */
			$db->exec("SET NAMES 'utf8'");
			break;
		case 'pgsql':
			/* Use UTF-8. */
			$db->exec("SET NAMES 'UTF8'");
			break;
		}

		return $db;
	}

	/**
	 * Check a password hash to see if it was hashed using the legacy hash algorithm (md5).
	 *
	 * @param string $password String to check.
	 * @return boolean True if the $password matches the format of an md5 sum.
	 */
	function password_is_legacy_hash($password) {
	    return (bool) preg_match('/^[0-9a-f]{32}$/', $password);
	}

	/**
	 * Compare password against hash stored in user object to determine if it is valid.
	 *
	 * If necessary it also updates the stored hash to the current format.
	 *
	 * @param stdClass $user (Password property may be updated).
	 * @param string $password Plain text password.
	 * @return bool True if password is valid.
	 */
	function validate_internal_user_password($user, $password) {
	    $CFG = $this->moodleconfig;

	    require_once($this->moodleroot .'/lib/password_compat/lib/password.php');


	    // If hash isn't a legacy (md5) hash, validate using the library function.
	    if (!$this->password_is_legacy_hash($user->password)) {
	        return password_verify($password, $user->password);
	    }

	    // Otherwise we need to check for a legacy (md5) hash instead. If the hash
	    // is valid we can then update it to the new algorithm.

	    $sitesalt = isset($CFG->passwordsaltmain) ? $CFG->passwordsaltmain : '';
	    $validated = false;

	    if ($user->password === md5($password.$sitesalt)
	            or $user->password === md5($password)
	            or $user->password === md5(addslashes($password).$sitesalt)
	            or $user->password === md5(addslashes($password))) {
	        // Note: we are intentionally using the addslashes() here because we
	        //       need to accept old password hashes of passwords with magic quotes.
	        $validated = true;

	    } else {
	        for ($i=1; $i<=20; $i++) { // 20 alternative salts should be enough, right?
	            $alt = 'passwordsaltalt'.$i;
	            if (!empty($CFG->$alt)) {
	                if ($user->password === md5($password.$CFG->$alt) or $user->password === md5(addslashes($password).$CFG->$alt)) {
	                    $validated = true;
	                    break;
	                }
	            }
	        }
	    }

	    return $validated;
	}


	/**
	 * Attempt to log in using the given username and password.
	 *
	 * On a successful login, this function should return the users attributes. On failure,
	 * it should throw an exception. If the error was caused by the user entering the wrong
	 * username or password, a SimpleSAML_Error_Error('WRONGUSERPASS') should be thrown.
	 *
	 * Note that both the username and the password are UTF-8 encoded.
	 *
	 * @param string $username  The username the user wrote.
	 * @param string $password  The password the user wrote.
	 * @return array  Associative array with the users attributes.
	 */
	protected function login($username, $password) {
		assert('is_string($username)');
		assert('is_string($password)');

		SimpleSAML_Logger::debug('sspmod_moodleauth_Auth_Source_UserPass:' . $this->authId . ': user: ' .
			$username);

		$db = $this->connect();
		try {
			$sth = $db->prepare('SELECT "username", "firstname", "lastname", "email", "idnumber", "alternatename", "city", "country", "institution", "department", "auth", "password" FROM "'.
				$this->moodleconfig->prefix.'user" AS "u" WHERE "u"."username" = :username AND "u"."suspended" = 0 AND "u"."deleted" = 0 AND "u"."auth" = :auth');
		} catch (PDOException $e) {
			throw new Exception('sspmod_moodleauth_Auth_Source_UserPass:' . $this->authId .
				': - Failed to prepare query: ' . $e->getMessage());
		}

		try {
			$res = $sth->execute(array('username' => $username, 'auth' => 'manual'));
		} catch (PDOException $e) {
			throw new Exception('sspmod_moodleauth_Auth_Source_UserPass:' . $this->authId .
				': - Failed to execute query: ' . $e->getMessage());
		}

		try {
			$data = $sth->fetchAll(PDO::FETCH_ASSOC);
		} catch (PDOException $e) {
			throw new Exception('sspmod_moodleauth_Auth_Source_UserPass:' . $this->authId .
				': - Failed to fetch result set: ' . $e->getMessage());
		}

		SimpleSAML_Logger::info('sspmod_moodleauth_Auth_Source_UserPass:' . $this->authId . ': Got ' . count($data) .
			' rows from database');

		if (count($data) != 1) {
			/* No rows returned - invalid username/password. */
			SimpleSAML_Logger::error('sspmod_moodleauth_Auth_Source_UserPass:' . $this->authId .
				': No rows in result set. Probably wrong username/password.');
			throw new SimpleSAML_Error_Error('WRONGUSERPASS');
		}
		$data = array_shift($data);
		SimpleSAML_Logger::debug('sspmod_moodleauth_Auth_Source_UserPass:' . $this->authId . ': data: ' . var_export($data, true));



		// $password = $this->encrypt_password($password, $data['salt'], '$2a$' . $this->moodleconfig->bcrypt_cost . '$', $this->moodleconfig->passwordsaltmain);
		SimpleSAML_Logger::debug('sspmod_moodleauth_Auth_Source_UserPass:' . $this->authId . ': password: ' . $password);
		if (!empty($data['password']) && $this->validate_internal_user_password((object)$data, $password)) {
			SimpleSAML_Logger::info('sspmod_moodleauth_Auth_Source_UserPass:' . $this->authId . ': user authenticated ');
		}
		else {
			SimpleSAML_Logger::error('sspmod_moodleauth_Auth_Source_UserPass:' . $this->authId .
				': No rows in result set. Probably wrong username/password.');
			throw new SimpleSAML_Error_Error('WRONGUSERPASS');
		}

		/* Extract attributes. We allow the resultset to consist of multiple rows. Attributes
		 * which are present in more than one row will become multivalued. NULL values and
		 * duplicate values will be skipped. All values will be converted to strings.
		 */
		$attributes = array();
		foreach ($data as $name => $value) {
			// remove sensitive values
			if (in_array($name, array('password', 'salt'))) {
				continue;
			}
			// drop empty values
			if ($value === NULL) {
				continue;
			}
			$value = (string)$value;
			if (!array_key_exists($name, $attributes)) {
				$attributes[$name] = array();
			}
			if (in_array($value, $attributes[$name], TRUE)) {
				/* Value already exists in attribute. */
				continue;
			}
			$attributes[$name][] = $value;
		}

		SimpleSAML_Logger::info('sspmod_moodleauth_Auth_Source_UserPass:' . $this->authId . ': Attributes: ' .
			var_export($attributes, true));

		return $attributes;
	}

}

?>