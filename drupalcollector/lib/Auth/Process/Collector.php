<?php

/**
 * Filter to validate MLEP User attributes as a backstop
 * check against poorly maintained LDAP directories
 * See docs directory.
 * based on the authorize:Authorize module
 *
 * @author Piers Harding
 * @package simpleSAMLphp
 * @version $Id$
 */

class sspmod_drupalcollector_Auth_Process_Collector extends SimpleSAML_Auth_ProcessingFilter {

    /**
     * Array of valid users. Each element is a regular expression. You should
     * user \ to escape special chars, like '.' etc.
     *
     */
    private $check_attributes = array();
    
    /**
     * Initialize this filter.
     * Validate configuration parameters.
     *
     * @param array $config  Configuration information about this filter.
     * @param mixed $reserved  For future use.
     */
    public function __construct($config, $reserved) {
        assert('is_array($config)');

        parent::__construct($config, $reserved);

        // set a backup one
        if (!isset($this->authId)) {
            $this->authId = 'drupalcollector';
        }
        
        /* Get the configuration for this module */    
        $drupalAuthConfig = new sspmod_drupalcollector_ConfigHelper($config,
            'Authentication processor ' . var_export($this->authId, TRUE));

        $drupalroot = $drupalAuthConfig->getDrupalroot();
        if (empty($drupalroot) || !is_dir($drupalroot)) {
            throw new Exception('Filter drupalcollector:Collector:  invalid drupalroot ' . var_export($drupalroot, TRUE));
        }

        $this->debug      = $drupalAuthConfig->getDebug();
        $this->is_staging = $drupalAuthConfig->getIsStaging();
        $this->autocreate = $drupalAuthConfig->getAutoCreate();
        $this->attributes = $drupalAuthConfig->getAttributes();
        $this->externalid = $drupalAuthConfig->getExternalId();
        $this->roles      = $drupalAuthConfig->getRoles();
        $this->stoprole   = $drupalAuthConfig->getStopRole();
        $this->redirect   = $drupalAuthConfig->getRedirect();

        define('DRUPAL_ROOT', $drupalroot);

        // from drupal authorize
        define('MAINTENANCE_MODE', 'update');
        
        /* Include the Drupal bootstrap */
        require_once DRUPAL_ROOT . '/includes/bootstrap.inc';
        require_once DRUPAL_ROOT . '/includes/session.inc';
        require_once DRUPAL_ROOT . '/includes/common.inc';
        require_once DRUPAL_ROOT . '/includes/file.inc';
        require_once DRUPAL_ROOT . '/includes/module.inc';
        
        /* Initialize the Drupal environment (and pray it doesn't break everything) */
        // we do not want to use DRUPAL_BOOTSTRAP_SESSION because that level of initialization
        // interacts negatively with SimpleSAMLphp. However, we need to fake the
        // Drupal watchdog out it won't complain about missing a uid. So, we need to 
        // create a fake user object with uid of 0 just before calling drupal_bootstrap().
        global $user;
        if (!$user) {
            $user = new stdClass();
        }
        $user->uid = 0;

        drupal_bootstrap(DRUPAL_BOOTSTRAP_VARIABLES);
        
        global $conf;

        // we need to be able to call Drupal user function so we load some required modules
        drupal_load('module', 'system');
        drupal_load('module', 'user');
        drupal_load('module', 'taxonomy');
        drupal_load('module', 'field');
        drupal_load('module', 'field_sql_storage');

        // this is from drupal authorize 
        drupal_language_initialize();
    }


    /**
     * Apply filter to validate attributes.
     *
     * @param array &$request  The current request
     */
    public function process(&$request) {
        $authorize = FALSE;
        assert('is_array($request)');
        assert('array_key_exists("Attributes", $request)');

        $attributes =& $request['Attributes'];

        // the external ID must exist
        SimpleSAML_Logger::debug('drupalcollector:Collector externalid: '. var_export($this->externalid, true));
        if (empty($attributes[$this->externalid])) {
            return $attributes;
        }
        // must be hashed as it runs out of space otherwise
        $authname = $attributes[$this->externalid][0];
        SimpleSAML_Logger::debug('drupalcollector:Collector authname: '. var_export($authname, true));
        if (isset($attributes['drupaluid']) && isset($attributes['drupaluid'][0])) {
            // load the user object from Drupal
            $drupaluser = user_load($attributes['drupaluid'][0]);
            SimpleSAML_Logger::debug('drupalcollector:Collector found user by drupaluid: '. var_export($drupaluser, true));
            // ensure that the remote user pointer exists
            if ($drupaluser) {
                $aid = db_query("SELECT aid FROM {authmap} WHERE module='simplesamlphp_auth' AND uid=:uid AND authname=:authname", array(':uid' => $drupaluser->uid, ':authname' => $authname))->fetchField();
                SimpleSAML_Logger::debug('drupalcollector:Collector authmap query: '. var_export($aid, true));
                if (!$aid) {
                    // create the link
                    $query = db_insert('authmap')
                      ->fields(array(
                        'uid' => $drupaluser->uid,
                        'authname' => $authname,
                        'module' => 'simplesamlphp_auth',
                      ))
                      ->execute();
                }
            }
        }
        else {
            // load the user object from Drupal using external Id
            SimpleSAML_Logger::debug('drupalcollector:Collector loading using authname: '. var_export($authname, true));
            $drupaluser = user_external_load($authname);
        }

        // back door for staging to relink names
        if (empty($drupaluser)) {
            if ($this->is_staging) {
                // we are cheating
                SimpleSAML_Logger::debug('drupalcollector:Collector IS STAGING');
                $username = $attributes['eduPersonPrincipalName'][0];
                $uid = db_query("SELECT uid FROM {users} WHERE name=:name", array(':name' => $username))->fetchField();
                if ($uid) {
                    $drupaluser = user_load($uid);
                    // create the link
                    $query = db_insert('authmap')
                      ->fields(array(
                        'uid' => $drupaluser->uid,
                        'authname' => $authname,
                        'module' => 'simplesamlphp_auth',
                      ))
                      ->execute();
                }
            }
        }
    
        // stop now if we don't know this user and there is no autocreate
        if (empty($drupaluser)) {
            if (!$this->autocreate) {
                SimpleSAML_Logger::debug('drupalcollector:Collector NO USER FOUND');
                return $attributes;
            }
            // create the missing account and then carry on
            else {
                // ensure the authname is not already used as a username
                $username = $attributes['eduPersonPrincipalName'][0];
                $uid = db_query("SELECT uid FROM {users} WHERE name=:name", array(':name' => $authname))->fetchField();
                if ($uid) {
                    // this is bad - the user should not exist
                    SimpleSAML_Logger::debug('drupalcollector:Collector conflicting uid: '. var_export($uid, true));
                    //SimpleSAML_Logger::debug('drupalcollector:Collector THIS IS GOING TO END BADLY: '. var_export($attributes, true));
                    //throw new SimpleSAML_Error_Exception('Username allready exists: '.$username);

                    // Rename them! --Jiri, Catalyst, 20.6.2012

                    $newname = $authname . '--' . $uid;
                    SimpleSAML_Logger::debug('drupalcollector:Collector renaming '.$uid.' from '.$authname.' to '.$newname);
                    db_update('users')
                        ->fields(array('name' => $newname))
                        ->condition('uid', $uid)
                        ->execute();
                }

                $_authmaps = db_query("SELECT aid
                    FROM {authmap}
                    WHERE module='simplesamlphp_auth'
                        AND authname=:authname",
                    array(':authname' => $authname)
                )->fetchAll();
                SimpleSAML_Logger::debug('drupalcollector: checking authmaps before db_transactions ' . var_export($_authmaps, 1));

                global $user;
                // start the transaction here, so that there is not commit until the username update is done
                $transaction = db_transaction();
                user_external_login_register($authname, 'simplesamlphp_auth');
                if ($user) {
             
                    // Populate roles based on configuration setting - TODO.
                    $roles = $this->rolepopulation($this->roles, $attributes);
                    $userinfo = array('roles' => $roles);
                    if (isset($attributes['givenName'])) {
                        $userinfo['field_firstname']['und'][0]['value'] = $attributes['givenName'][0];
                    }
                    if (isset($attributes['sn'])) {
                        $userinfo['field_lastname']['und'][0]['value'] = $attributes['sn'][0];
                    }
                    $user = user_save($user, $userinfo);

                    // Append the UID to the username to make it more unique.
                    // This is necessary because sometimes one service's
                    // $username clashes with another service's $authname; for
                    // instance, Google can give us somebody's Facebook e-mail
                    // address as the $username and then later it'll clash with
                    // the Facebook $authname.
                    $username .= '-' . $user->uid;

                    // set the email address, and username
                    $mail = $attributes['mail'][0];
                    SimpleSAML_Logger::debug('drupalcollector:Collector setting mail: '.var_export($mail, true));
                    db_update('users')
                        ->fields(array('name' => $username, 'mail' => $mail))
                        ->condition('uid', $user->uid)
                        ->execute();
                }

                // read back the new user
                $drupaluser = user_external_load($authname);
                SimpleSAML_Logger::debug('drupalcollector:Collector created user: '.var_export($drupaluser, true));
                if (empty($drupaluser)) {
                    SimpleSAML_Logger::debug('drupalcollector:Collector NO USER FOUND EVEN AFTER CREATION');
                    return $attributes;
                }
            }
        }

        if ($this->stoprole && array_key_exists($this->stoprole, $drupaluser->roles)) {
            if (isset($request['saml:RelayState']) && !preg_match('/(drupal|my)/', $request['saml:RelayState'])) {
                // you are not a confirmed user, so go back to drupal
                SimpleSAML_Utilities::redirect($this->redirect);
                die();
            }
        }

        // get all the attributes out of the user object
        $userAttrs = get_object_vars($drupaluser);
        
        // define some variables to use as arrays
        $userAttrNames = null;
        //$attributes    = null;
        
        // figure out which attributes to include
        if(NULL == $this->attributes){
           $userKeys = array_keys($userAttrs);
           
           // populate the attribute naming array
           foreach($userKeys as $userKey){
              $userAttrNames[$userKey] = $userKey;
           }
           
        }else{
           // populate the array of attribute keys
           // populate the attribute naming array
           foreach($this->attributes as $confAttr){
           
              $userKeys[] = $confAttr['drupaluservar'];
              $userAttrNames[$confAttr['drupaluservar']] = $confAttr['callit'];
           
           }
           
        }
           
        // an array of the keys that should never be included
        // (e.g., pass)
        $skipKeys = array('pass');

        // package up the user attributes    
        foreach($userKeys as $userKey){

          // skip any keys that should never be included
          if(!in_array($userKey, $skipKeys)){

            if(   is_string($userAttrs[$userKey]) 
               || is_numeric($userAttrs[$userKey])
               || is_bool($userAttrs[$userKey])    ){

               $attributes[$userAttrNames[$userKey]] = array($userAttrs[$userKey]);

            }elseif(is_array($userAttrs[$userKey])){

               // if the field is a field module field, special handling is required
               if(substr($userKey,0,6) == 'field_'){
                  if (isset($userAttrs[$userKey]['und'][0]['safe_value'])) {
                        $attributes[$userAttrNames[$userKey]] = array($userAttrs[$userKey]['und'][0]['safe_value']);
                  }
                  else {
                        $attributes[$userAttrNames[$userKey]] = array($userAttrs[$userKey]['und'][0]['value']);
                  }
               }else{
               // otherwise treat it like a normal array
                  $attributes[$userAttrNames[$userKey]] = $userAttrs[$userKey];
               }
            }

          }
        }
        $tid = (isset($userAttrs['field__user_tag']['und'][0]['tid']) ? $userAttrs['field__user_tag']['und'][0]['tid'] : false);
        if ($tid) {
            $tax = taxonomy_term_load($tid);
            if ($tax) {
                $attributes['user_tag'] = array($tax->name);
            }
        }

        if (isset($drupaluser->field_user_tag) and $tid = $drupaluser->field_user_tag['und'][0]['tid']) {
            $tax = taxonomy_term_load($drupaluser->field_user_tag['und'][0]['tid']);
            if ($tax) {
                $tax_name = $tax->name;
                error_log('TAXONOMY: '.$tax_name);
            }
        }

        // Get gateways related variables

        if (isset($drupaluser)) {
            $attributes['gateways_creator'] = array(user_access('create gateway2 content', $drupaluser));
            if (is_callable('plane_gateways2_gateways_user')) {
              $attributes['gateways_user'] = array(plane_gateways2_gateways_user($drupaluser->uid));
            }
        }
        SimpleSAML_Logger::debug('drupalcollector:Collector final attributes: '.var_export($attributes, true));
        return $attributes;

    }


    /**
     * Evaluates a role rule.
     *
     * @param $roleruleevaluation
     *   An array containing the role rule to evaluate.
     *
     * @param $attributes
     *   An array containing the identity attributes.
     *
     * @return
     *   An array containing role value and the attribute, or FALSE.
     */
    private function evaulaterolerule($roleruleevaluation, $attributes) {
    
        if (!array_key_exists($roleruleevaluation[0], $attributes)) return FALSE;
        $attribute = $attributes[$roleruleevaluation[0]];
    
        switch ($roleruleevaluation[1]) {
            case '=' :
                return in_array($roleruleevaluation[2], $attribute);
    
            case '@=' :
                $dc = explode('@', $attribute[0]);
                if (count($dc) != 2) return FALSE;
                return ($dc[1] == $roleruleevaluation[2]);
        }
    
        return FALSE;
    }



    /**
     * Performs role population.
     *
     * @param $rolemap
     *   A string containing the role map.
     *
     * @return
     *   An array containing user's roles.
     */
    private function rolepopulation($rolemap, $attributes) {
    
        $roles = array();
    
        if (empty($rolemap)) return $roles;
        $rolerules = explode('|', $rolemap);
        foreach ($rolerules AS $rolerule) {
            $roleruledecompose = explode(':', $rolerule);
            $roleid = $roleruledecompose[0];
            $roleruleevaluations = (isset($roleruledecompose[1]) ? explode(';', $roleruledecompose[1]) : array());
            $addnew = TRUE;
            foreach ($roleruleevaluations AS $roleruleevaluation) {
                $roleruleevaluationdc = explode(',', $roleruleevaluation);
                if (!$this->evaulaterolerule($roleruleevaluationdc, $attributes)) $addnew = FALSE;
            }
            if ($addnew) {
                $roles[$roleid] = $roleid;
            }
        }
        return $roles;
    }
}

?>
