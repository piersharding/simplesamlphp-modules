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
class sspmod_maharaauth_Auth_Source_UserPass extends sspmod_core_Auth_UserPassBase {


	/**
	 * The root of the Mahara instance to integrate with.
	 */
	private $mahararoot;

	/**
	 * The config for mahara.
	 */
	private $maharaconfig;

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
		foreach (array('mahararoot') as $param) {
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

		$this->mahararoot = $config['mahararoot'];
		// Catch anything that goes wrong in init.php
		ob_start();
		require($this->mahararoot . '/config.php');
	    $errors = trim(ob_get_contents());
		ob_end_clean();

		$bcrypt_cost = (isset($cfg->bcrypt_cost) ? $cfg->bcrypt_cost : NULL);
		// bcrypt_cost is the cost parameter passed as part of the bcrypt hash
		// See http://php.net/manual/en/function.crypt.php
		// The value is a 2 digit number in the range of 04-31
		if (!$bcrypt_cost || !is_int($bcrypt_cost) || $bcrypt_cost < 4 || $bcrypt_cost > 31) {
		    $bcrypt_cost = 12;
		}
		$cfg->bcrypt_cost = sprintf('%02d', $bcrypt_cost);

		// passwordsaltmain - ensure it exists
		$cfg->passwordsaltmain = (isset($cfg->passwordsaltmain) ? $cfg->passwordsaltmain : '');

		$this->maharaconfig = $cfg;

		SimpleSAML_Logger::info('sspmod_maharaauth_Auth_Source_UserPass:' . $this->authId . ': config: ' .
			var_export($this->maharaconfig, true));

		if (preg_match('/postgres/', $cfg->dbtype)) {
			$dbtype = 'pgsql';
		}
		else if (preg_match('/mysql/', $cfg->dbtype)) {
			$dbtype = 'mysql';
		}
		else {
			$dbtype = $this->dbtype;
		}
		$this->dsn = $dbtype.':host='.$cfg->dbhost.($cfg->dbport ? ';port=' : '').';dbname='.$cfg->dbname;
		// 'pgsql:host=localhost;port=5432;dbname=maharadev'

		SimpleSAML_Logger::info('sspmod_maharaauth_Auth_Source_UserPass:' . $this->authId . ': dsn: ' .
			$this->dsn);
	}



	/**
	 * Create a database connection.
	 *
	 * @return PDO  The database connection.
	 */
	private function connect() {
		try {
			$db = new PDO($this->dsn, $this->maharaconfig->dbuser, $this->maharaconfig->dbpass);
		} catch (PDOException $e) {
			throw new Exception('maharaauth:' . $this->authId . ': - Failed to connect to \'' .
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
    * Given a password and an optional salt, encrypt the given password.
    *
    * Passwords are stored in SHA1 form.
    *
    * @param string $password The password to encrypt
    * @param string $salt     The salt to use to encrypt the password
    * @param string $alg      The algorithm to use, defaults to $6$ which is SHA512
    * @param string $sitesalt A salt to combine with the user's salt to add an extra layer or salting
    * @todo salt mandatory
    */
    public function encrypt_password($password, $salt='', $alg='$6$', $sitesalt='') {
        if ($salt == '') {
            $salt = substr(md5(rand(1000000, 9999999)), 2, 8);
        }
        if ($alg == '$6$') { // $6$ is the identifier for the SHA512 algorithm
            // Return a hash which is sha512(originalHash, salt), where original is sha1(salt + password)
            $password = sha1($salt . $password);
            // Generate a salt based on a supplied salt and the passwordsaltmain
            $fullsalt = substr(md5($sitesalt . $salt), 0, 16); // SHA512 expects 16 chars of salt
        }
        else { // This is most likely bcrypt $2a$, but any other algorithm can take up to 22 chars of salt
            // Generate a salt based on a supplied salt and the passwordsaltmain
            $fullsalt = substr(md5($sitesalt . $salt), 0, 22); // bcrypt expects 22 chars of salt
        }
        $hash = crypt($password, $alg . $fullsalt);
        // Strip out the computed salt
        // We strip out the salt hide the computed salt (in case the sitesalt was used which isn't in the database)
        $hash = substr($hash, 0, strlen($alg)) . substr($hash, strlen($alg)+strlen($fullsalt));
        return $hash;
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

		SimpleSAML_Logger::debug('sspmod_maharaauth_Auth_Source_UserPass:' . $this->authId . ': user: ' .
			$username);

		$db = $this->connect();
		try {
			$sth = $db->prepare('SELECT "username", "firstname", "lastname", "email", "staff", "admin", "studentid", "preferredname", "ai"."institution", "password", "salt" FROM "usr" AS "u" JOIN "auth_instance" AS "ai" ON "u"."authinstance" = "ai"."id" WHERE "u"."username" = :username AND "u"."active" = 1 AND "u"."deleted" = 0');
		} catch (PDOException $e) {
			throw new Exception('sspmod_maharaauth_Auth_Source_UserPass:' . $this->authId .
				': - Failed to prepare query: ' . $e->getMessage());
		}

		try {
			$res = $sth->execute(array('username' => $username));
		} catch (PDOException $e) {
			throw new Exception('sspmod_maharaauth_Auth_Source_UserPass:' . $this->authId .
				': - Failed to execute query: ' . $e->getMessage());
		}

		try {
			$data = $sth->fetchAll(PDO::FETCH_ASSOC);
		} catch (PDOException $e) {
			throw new Exception('sspmod_maharaauth_Auth_Source_UserPass:' . $this->authId .
				': - Failed to fetch result set: ' . $e->getMessage());
		}

		SimpleSAML_Logger::info('sspmod_maharaauth_Auth_Source_UserPass:' . $this->authId . ': Got ' . count($data) .
			' rows from database');

		if (count($data) != 1) {
			/* No rows returned - invalid username/password. */
			SimpleSAML_Logger::error('sspmod_maharaauth_Auth_Source_UserPass:' . $this->authId .
				': No rows in result set. Probably wrong username/password.');
			throw new SimpleSAML_Error_Error('WRONGUSERPASS');
		}
		$data = array_shift($data);
		SimpleSAML_Logger::debug('sspmod_maharaauth_Auth_Source_UserPass:' . $this->authId . ': data: ' . var_export($data, true));
		$password = $this->encrypt_password($password, $data['salt'], '$2a$' . $this->maharaconfig->bcrypt_cost . '$', $this->maharaconfig->passwordsaltmain);
		SimpleSAML_Logger::debug('sspmod_maharaauth_Auth_Source_UserPass:' . $this->authId . ': password: ' . $password);
		if (!empty($data['password']) && $data['password'] == $password) {
			SimpleSAML_Logger::info('sspmod_maharaauth_Auth_Source_UserPass:' . $this->authId . ': user authenticated ');
		}
		else {
			SimpleSAML_Logger::error('sspmod_maharaauth_Auth_Source_UserPass:' . $this->authId .
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

		// add institution membership
		try {
			$sth = $db->prepare('SELECT "ai"."institution" from "auth_remote_user" AS "aru" JOIN "usr" AS "u" ON "aru"."localusr" = "u"."id" JOIN "auth_instance" AS "ai" ON "aru"."authinstance" = "ai"."id" JOIN "institution" AS "i" ON "i"."name" = "ai"."institution" WHERE "u"."username" = :username AND "u"."active" = 1 AND "u"."deleted" = 0');
		} catch (PDOException $e) {
			throw new Exception('sspmod_maharaauth_Auth_Source_UserPass:' . $this->authId .
				': - Failed to prepare query: ' . $e->getMessage());
		}

		try {
			$res = $sth->execute(array('username' => $username));
		} catch (PDOException $e) {
			throw new Exception('sspmod_maharaauth_Auth_Source_UserPass:' . $this->authId .
				': - Failed to execute query: ' . $e->getMessage());
		}

		try {
			$data = $sth->fetchAll(PDO::FETCH_ASSOC);
		} catch (PDOException $e) {
			throw new Exception('sspmod_maharaauth_Auth_Source_UserPass:' . $this->authId .
				': - Failed to fetch result set: ' . $e->getMessage());
		}

		SimpleSAML_Logger::debug('sspmod_maharaauth_Auth_Source_UserPass:' . $this->authId . ': Got ' . count($data) .
			' rows from database');
		foreach ($data as $row) {
			foreach ($row as $name => $value) {
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
		}
		SimpleSAML_Logger::info('sspmod_maharaauth_Auth_Source_UserPass:' . $this->authId . ': Attributes: ' .
			var_export($attributes, true));

		return $attributes;
	}

}

?>