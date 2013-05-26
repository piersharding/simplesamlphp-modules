<?php

/**
 * avsaqc: SimpleSAMLphp Attribute Query client for the Address Verification Service
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
 * Copied from the attributequeryconsumer plugin
 * provided by
 *
 * @author Sixto Martin, Yaco Sistemas. <smartin@yaco.es>
 * @package simpleSAMLphp
 * @version $Id$
 */

class sspmod_authigovt_AQC {

    public function sendQuery($aqsUrl, $sourceId, $partner, $nameId, $reqAttributes=array(), $attrNameFormat=SAML2_Const::NAMEFORMAT_UNSPECIFIED) {
	    assert('is_string($aqsUrl)');
	    assert('is_string($sourceId)');
	    assert('is_array($nameId)');

	    SimpleSAML_Logger::debug('AttributeQueryConsumer - Sending test request to '.$aqsUrl);
        SimpleSAML_Logger::debug('AttributeQueryConsumer - sourceId '.$sourceId);
        SimpleSAML_Logger::debug('AttributeQueryConsumer - partner '.$partner);

	    $source = SimpleSAML_Auth_Source::getById($sourceId, 'sspmod_saml_Auth_Source_SP');

        if (!($source instanceof sspmod_saml_Auth_Source_SP)) {
                throw new SimpleSAML_Error_NotFound('Source isn\'t a SAML SP: ' . var_export($sourceId, TRUE));
        }

        if (isset($nameId['Format']) && !empty($nameId['Format'])) {
            $nameFormat = $nameId['Format'];
        }
        else {
            $nameFormat = SAML2_Const::NAMEFORMAT_UNSPECIFIED;
        }

        $spEntityId = $source->getEntityId();

        $query = new SAML2_AttributeQuery();

        $query->setRelayState($nameId['Value']);

        $query->setDestination($aqsUrl);
        $query->setIssuer($spEntityId);
        $query->setNameId($nameId);
        $query->setAttributeNameFormat($nameFormat);

        // set Consent attribute for RealMe Testing - this is a hack !!!!!!!
!        $consent = 'ConsentType=IntegrationConsent&ConsentAttributes=null&ConsentEventDate='.date('Y-m-d\TH:i:s.000O', time() - 24 * 60 * 60).
                    '&ConsentDecision=ConsentGiven&ConsentCapturedAt=RealMe&TokenIssuanceDate='.date('Y-m-d\TH:i:s.000O', time() - 60 * 60).
                    '&TokenExpiryDate='.date('Y-m-d\TH:i:s.000O', time() + 24 * 60 * 60);
        // compute signature
        $sig  = '';
        $idpMetadata = $source->getMetadata();
        $privatekey = SimpleSAML_Utilities::loadPrivateKey($idpMetadata, TRUE);

        $privatekey = openssl_pkey_get_private($privatekey['PEM']);
        $bool = openssl_sign($consent, $sig, $privatekey);
        if (!$bool) {
            throw new Exception('Reading private key failed');
        }
        $consent = $consent.'&Signature='.base64_encode($sig).'&SigAlg=SHA1WithRSA';
        $consent = htmlspecialchars($consent);
        $query->Consent = $consent;

        if(!empty($reqAttributes)) {
            $query->setAttributes($reqAttributes);
            $query->setAttributeNameFormat($attrNameFormat);
        }


        $metadata = SimpleSAML_Metadata_MetaDataStorageHandler::getMetadataHandler();

	    $source = SimpleSAML_Auth_Source::getById($sourceId, 'sspmod_saml_Auth_Source_SP');
	    $spMetadata = $source->getMetadata();

        $idpMetadata = $metadata->getMetaDataConfig($partner, 'saml20-sp-remote');

        /* Sign the request */
        /// source, dest
        SimpleSAML_Logger::debug('AttributeQueryConsumer - source entityId: '.$spMetadata->getString('entityid').' destination entityId: '.$partner);
        sspmod_saml_Message::addSign($spMetadata, $idpMetadata, $query);

        $soap = new SAML2_SOAPClient();

        $response = $soap->send($query, $spMetadata, $idpMetadata);

		if (!$response->isSuccess()) {
			throw new Exception('Received error from Attribute Query Response: '.var_export($response->getStatus(), true));
		}

	    $assertion = sspmod_saml_Message::processResponse($spMetadata, $idpMetadata, $response);
	    if (count($assertion) > 1) {
		    throw new SimpleSAML_Error_Exception('More than one assertion in received response.');
	    }
	    $assertion = $assertion[0];

		return $assertion;

    }
}

?>
