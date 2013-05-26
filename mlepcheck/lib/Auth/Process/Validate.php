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

class sspmod_mlepcheck_Auth_Process_Validate extends SimpleSAML_Auth_ProcessingFilter {

    /**
     * Array of valid users. Each element is a regular expression. You should
     * user \ to escape special chars, like '.' etc.
     *
     */
    private $check_attributes = array();

    // data validation scheme for mlep values
    private $valid_attribute_values = 
                     array(
                            'mlepRole' => array('mandatory' => true, 'single' => true, 'match' => array('Student', 'TeachingStaff', 'NonTeachingStaff', 'ParentCaregiver', 'Alumni')),
                            'mlepSmsPersonId' => array('mandatory' => true, 'single' => true, 'match' => '/[a-zA-Z0-9]+/'),
                            'mlepStudentNSN' => array('mandatory' => false, 'single' => true, 'match' => '/^\d{10}$/'),
                            'mlepUsername' => array('mandatory' => false, 'single' => true, 'match' => '/.+/'),
                            'mlepFirstAttending' => array('mandatory' => true, 'single' => true, 'match' => '/^\d{4}\-\d{2}\-\d{2}$/', 'group' => array('Student')),
                            'mlepLastAttendance' => array('mandatory' => false, 'single' => true, 'match' => '/^\d{4}\-\d{2}\-\d{2}$/', 'group' => array('Student')),
                            'mlepFirstName' => array('mandatory' => true, 'single' => true, 'match' => '/.+/'),
                            'mlepLastName' => array('mandatory' => true, 'single' => true, 'match' => '/.+/'),
                            'mlepPreferredName' => array('mandatory' => false, 'single' => true, 'match' => '/.+/'),
                            'mlepAssociatedNSN' => array('mandatory' => true, 'single' => false, 
                                                         'match' => '/^\d{10}$/', 'group' => array('ParentCaregiver')),
                            'mlepEmail' => array('mandatory' => false, 'single' => true, 'match' => '#^[-!\#$%&\'*+\\/0-9=?A-Z^_`a-z{|}~]+(\.[-!\#$%&\'*+\\/0-9=?A-Z^_`a-z{|}~]+)*@[-!\#$%&\'*+\\/0-9=?A-Z^_`a-z{|}~]+\.[-!\#$%&\'*+\\./0-9=?A-Z^_`a-z{|}~]+$#'),
                            'mlepOrganisation' => array('mandatory' => true, 'single' => true, 'match' => '/^[\w\d\.-]+$/'),
                            // other common values
                            'uid' => array('mandatory' => false, 'single' => true, 'match' => '/.+/'),
                            'sAMAccountName' => array('mandatory' => false, 'single' => true, 'match' => '/.+/'),
                            'mail' => array('mandatory' => false, 'single' => true, 'match' => '#^[-!\#$%&\'*+\\/0-9=?A-Z^_`a-z{|}~]+(\.[-!\#$%&\'*+\\/0-9=?A-Z^_`a-z{|}~]+)*@[-!\#$%&\'*+\\/0-9=?A-Z^_`a-z{|}~]+\.[-!\#$%&\'*+\\./0-9=?A-Z^_`a-z{|}~]+$#'),
                            // EPPN is like an email address
                            'eduPersonPrincipalName' => array('mandatory' => false, 'single' => true, 'match' => '#^[-!\#$%&\'*+\\/0-9=?A-Z^_`a-z{|}~]+(\.[-!\#$%&\'*+\\/0-9=?A-Z^_`a-z{|}~]+)*@[-!\#$%&\'*+\\/0-9=?A-Z^_`a-z{|}~]+\.[-!\#$%&\'*+\\./0-9=?A-Z^_`a-z{|}~]+$#'),
                     );
    
    /**
     * Initialize this filter.
     * Validate configuration parameters.
     *
     * @param array $config  Configuration information about this filter.
     * @param mixed $reserved  For future use.
     */
    public function __construct($config, $reserved) {
        parent::__construct($config, $reserved);
        assert('is_array($config)');
        if (isset($config['check']) && is_array($config['check']) && !empty($config['check'])) {
            foreach ($config['check'] as $attribute => $test) {
                // list of values as opposed to an array of tests
                if (is_int($attribute)) {
                    $attribute = $test;
                    $test = null;
                }
                if (isset($this->valid_attribute_values[$attribute])) {
                    if ($test) {
                        $this->check_attributes[$attribute] = $test;
                    }
                    else {
                        $this->check_attributes[$attribute] = $this->valid_attribute_values[$attribute];
                    }
                }
                else {
                    // check that must-have test values are present
                    if (is_array($test) && isset($test['mandatory']) && isset($test['single']) && isset($test['match'])) {
                        $this->check_attributes[$attribute] = $test;
                    }
                    else {
                        throw new Exception('Filter mlepcheck:Authorize: incorrect Attribute configured: ' . var_export($attribute, TRUE));
                    }
                }
            }
        }
        else {
            $this->check_attributes = $this->valid_attribute_values;
        }
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

        $ok = true;
        
        // first find the mlepRole
        $role = false;
        if (isset($attributes['mlepRole']) && !empty($attributes['mlepRole'])) {
            if (is_array($attributes['mlepRole'])) {
                $role = $attributes['mlepRole'][0];
            }
            else {
                $role = $attributes['mlepRole'];
            }
        }
        if (!$role || !in_array($role, $this->valid_attribute_values['mlepRole']['match'])) {
            // fail
            $ok = false;
            SimpleSAML_Logger::warning('mlepcheck::Validate: ' .
                                       'mlepRole is invalid ' .
                                       var_export($role, TRUE));
        }
        else {
            foreach ($this->check_attributes as $name => $checks) {
                // value must be present
                $values = array();
                if (array_key_exists($name, $attributes)) {
                    $values = $attributes[$name];
                    if (!is_array($values)) {
                        if ($values != null && $values != false) { // could be 0
                            $values = array($values);
                        }
                        else {
                            $values = array();
                        }
                    }
                }
                
                // check mandatory - but not in required group
                if(empty($values) && $checks['mandatory'] && isset($checks['group']) && !in_array($role, $checks['group'])) {
                    // exempt if group check fails on mandatory value
                    continue;
                }
                
                // must have value
                if(empty($values) && $checks['mandatory']) {
                    $ok = false;
                    SimpleSAML_Logger::warning('mlepcheck::Validate: ' .
                                               'mandatory value ' . $name . ' is empty ' .
                                               var_export($values, TRUE));
                    break;
                }

                // check that user is in correct group - exempt them from the check if they aren't
                if (isset($checks['group']) && !in_array($role, $checks['group'])) {
                    continue;
                }
                
                // check single value
                if ($checks['single'] && count($values) > 1) {
                    $ok = false;
                    SimpleSAML_Logger::warning('mlepcheck::Validate: ' .
                                               'single value check failed for ' . $name .
                                               var_export($values, TRUE));
                    break;
                }
                
                // check each value
                foreach ($values as $value){
                    // list value type check
                    if (is_array($checks['match'])) {
                        if (!in_array($value, $checks['match'])) {
                            SimpleSAML_Logger::warning('mlepcheck::Validate: ' .
                                                       'valid value check (list) failed for ' . $name .
                                                       var_export($value, TRUE));
                            $ok = false;
                        }
                    }
                    // regex match
                    else {
                        if (!preg_match($checks['match'], $value)) {
                            SimpleSAML_Logger::warning('mlepcheck::Validate: ' .
                                                       'valid value check (regex) failed for ' . $name . ' ' .
                                                       var_export($value, TRUE));
                            $ok = false;
                        }
                    }
                }
                // jump out
                if (!$ok) {
                    break;
                }
            }
        }
        if (!$ok){
            // we piggy back on the authorize::Authorize module            
            /* Save state and redirect to 403 page. */
            $id = SimpleSAML_Auth_State::saveState($request,
                'authorize:Authorize');
            $url = SimpleSAML_Module::getModuleURL(
                'authorize/authorize_403.php');
            SimpleSAML_Utilities::redirect($url, array('StateId' => $id));
        }
    }
}

?>
