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
 * Extended Security signing object
 * Add methods for adding thumbprint instead of X509 cert data
 *
 */

class sspmod_authigovt_XMLSecurityDSigExtended  extends XMLSecurityDSig {

    /**
     * Add a certificate thumbprint to the signature
     *
     * @param DOMElement $parentRef the parent element 
     * @param String $cert the public certificate to get the thumbprint from
     * @param String $xpath query to discover thumbprint position
     */
    static function staticAddThumbprint($parentRef, $cert, $xpath) {
        $cert = preg_replace('/(\n|\r)/', "", preg_replace("/-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----/","", $cert));
        $b64 = base64_decode($cert);
        $thumbprint = base64_encode(sha1($b64, true));
        if (! $parentRef instanceof DOMElement) {
            throw new Exception('Invalid parent Node parameter');
        }
        $baseDoc = $parentRef->ownerDocument;

        if (empty($xpath)) {
            $xpath = new DOMXPath($parentRef->ownerDocument);
            $xpath->registerNamespace('secdsig', XMLSecurityDSig::XMLDSIGNS);
        }
        $query = "./secdsig:KeyInfo";
        $nodeset = $xpath->query($query, $parentRef);
        $keyInfo = $nodeset->item(0);
        if (! $keyInfo) {
            $inserted = FALSE;
            $keyInfo = $baseDoc->createElementNS(XMLSecurityDSig::XMLDSIGNS, 'ds:KeyInfo');

            $query = "./secdsig:Object";
            $nodeset = $xpath->query($query, $parentRef);
            if ($sObject = $nodeset->item(0)) {
                $sObject->parentNode->insertBefore($keyInfo, $sObject);
                $inserted = TRUE;
            }

            if (! $inserted) {
                $parentRef->appendChild($keyInfo);
            }
        }

        $TokenRefNode = $baseDoc->createElement('wsse:SecurityTokenReference');
        $keyInfo->appendChild($TokenRefNode);
        $keyIdentifierNode = $baseDoc->createElement('wsse:KeyIdentifier', $thumbprint);
        $keyIdentifierNode->setAttribute('EncodingType', "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary");
        $keyIdentifierNode->setAttribute('ValueType', "http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#ThumbprintSHA1");
        $TokenRefNode->appendChild($keyIdentifierNode);
    }

     /**
     * Add a certificate thumbprint to the signature
     *
     * @param String $cert the public certificate to get the thumbprint from
     */
    public function addThumbprint($cert) {
        $xpath = new DOMXPath($this->sigNode->ownerDocument);
        $xpath->registerNamespace('secdsig', XMLSecurityDSig::XMLDSIGNS);
        self::staticAddThumbprint($this->sigNode, $cert, $xpath);
    }
}

