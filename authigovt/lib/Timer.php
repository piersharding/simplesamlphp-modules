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
 * Timer object for tracking various timing intervals
 *
 */

class sspmod_authigovt_Timer {
    private $start;
    private $typeTag;
    private $destination;
    public $issuer;
    public $id;

    /**
     * create a timing object and seed the start time
     */
    public function __construct($typeTag, $destination, $issuer="", $id=null) {
        $this->start = microtime(true);
        $this->typeTag = $typeTag;
        $this->destination = $destination;
        $this->issuer = $issuer;
        if ($id == null) {
            $id = XMLSecurityDSig::generate_GUID();
        }
        $this->id = $id;
    }

    /**
     * calculate the interval and format the microtime
     * @return string time interval resolution up to 1000ths
     */
    public function finish($status) {
        $time = sprintf("%.03f", microtime(true) - $this->start);
        SimpleSAML_Logger::stats($this->typeTag . ' ' . $this->destination . ' ' . $this->issuer . ' ' . $time. ' '.$status.' ['.$this->id.']');
    }
}
