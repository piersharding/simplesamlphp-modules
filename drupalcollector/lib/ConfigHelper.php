<?php

/**
 * Drupal authentication source configuration parser.
 *
 * Copyright SIL International, Steve Moitozo, <steve_moitozo@sil.org>, http://www.sil.org 
 *
 * This class is a Drupal authentication source which authenticates users
 * against a Drupal site located on the same server.
 *
 *
 * The homepage of this project: http://code.google.com/p/drupalauth/
 *
 * See the drupalauth-entry in config-templates/authsources.php for information about
 * configuration of these options.
 *
 * @author Steve Moitozo <steve_moitozo@sil.org>, SIL International
 * @package drupalauth
 * @version $Id$
 */
class sspmod_drupalcollector_ConfigHelper {


	/**
	 * String with the location of this configuration.
	 * Used for error reporting.
	 */
	private $location;


	/**
	 * The filesystem path to the Drupal directory
	 */
	private $drupalroot;


	/**
	 * The externalid attribute
	 */
	private $externalid;


	/**
	 * The roles
	 */
	private $roles;


	/**
	 * The stop role
	 */
	private $stoprole;


	/**
	 * The stop role redirect to
	 */
	private $redirect;


	/**
	 * Whether debug output is enabled.
	 *
	 * @var bool
	 */
	private $debug;


    /**
     * Whether this is staging
     *
     * @var bool
     */
    private $is_staging;


	/**
	 * Whether to auto create users
	 *
	 * @var bool
	 */
	private $autocreate;


	/**
	 * The attributes we should fetch. Can be NULL in which case we will fetch all attributes.
	 */
	private $attributes;


	/**
	 * Constructor for this configuration parser.
	 *
	 * @param array $config  Configuration.
	 * @param string $location  The location of this configuration. Used for error reporting.
	 */
	public function __construct($config, $location) {
		assert('is_array($config)');
		assert('is_string($location)');

		$this->location = $location;

		/* Parse configuration. */
		$config = SimpleSAML_Configuration::loadFromArray($config, $location);

		$this->drupalroot = $config->getString('drupalroot');
		$this->debug = $config->getBoolean('debug', FALSE);
        $this->is_staging = $config->getBoolean('isstaging', FALSE);
		$this->attributes = $config->getArray('attributes', NULL);
		$this->externalid = $config->getString('externalid');
		$this->autocreate = $config->getBoolean('autocreate', FALSE);
		$this->roles = $config->getString('roles');
		$this->stoprole = $config->getString('stoprole', 0);
		$this->redirect = $config->getString('redirect', '');

	}
	

	/**
	 * Return the debug
	 *
	 * @param boolean $debug whether or not debugging should be turned on
	 */
	public function getDebug() {
	   return $this->debug; 
	}

    /**
     * Return the staging indicator
     *
     * @param boolean $is_staging whether or not we are on staging
     */
    public function getIsStaging() {
       return $this->is_staging;
    }

	/**
	 * Return the drupaldir
	 *
	 * @param string $drupalroot the directory of the Drupal site
	 */
	public function getDrupalroot() {
	   return $this->drupalroot; 
	}

	/**
	 * Return the externalid
	 *
	 * @param string $externalid the externalid attribute
	 */
	public function getExternalId() {
	   return $this->externalid; 
	}

	/**
	 * Return the roles
	 *
	 * @param string $roles the roles attribute
	 */
	public function getRoles() {
	   return $this->roles; 
	}

	/**
	 * Return the stop role
	 *
	 * @param integer $stoprole the role that will cause a user to redirect
	 */
	public function getStopRole() {
	   return $this->stoprole; 
	}

	/**
	 * Return the stop role redirect target
	 *
	 * @param string $redirect the redirect URL on matching the stop role
	 */
	public function getRedirect() {
	   return $this->redirect; 
	}

	/**
	 * Return the autocreate flag
	 *
	 * @param boolean $autocreate
	 */
	public function getAutoCreate() {
	   return $this->autocreate; 
	}
		

	/**
	 * Return the attributes
	 *
	 * @param array $attributes the array of Drupal attributes to use, NULL means use all available attributes
	 */
	public function getAttributes() {
	   return $this->attributes; 
	}

}
