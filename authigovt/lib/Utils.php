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
 * Utility functions for RequestSecurityToken funcionality
 *
 */

class sspmod_authigovt_Utils {

    protected $query;
    public $config;

    const NS_WST = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/";

    const RST_ISSUE = 'http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue';

    const RST_VALIDATE = 'http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Validate';

    const SOAP_VERSION12 = '1.2';

    // iCMS API call timeout - 6 seconds is far too generous
    const ICMS_CALL_TIMEOUT = 6;

    /**
     * Query a document based on RST namespaces
     *
     * @param DOMElement $node an XML element.
     * @param String $query  an XPath query
     * @return DOMElement
     */
    public static function xpQuery(DOMNode $node, $query) {
        assert('is_string($query)');

        if ($node instanceof DOMDocument) {
            $doc = $node;
        } else {
            $doc = $node->ownerDocument;
        }

        $xpCache = new DOMXPath($doc);
        $xpCache->registerNamespace('soap', 'http://www.w3.org/2003/05/soap-envelope');
        $xpCache->registerNamespace('wsa', 'http://www.w3.org/2005/08/addressing');
        $xpCache->registerNamespace('wsse', 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd');
        $xpCache->registerNamespace('wsu', 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd');
        $xpCache->registerNamespace('wst', sspmod_authigovt_Utils::NS_WST);

        $results = $xpCache->query($query, $node);
        $ret = array();
        for ($i = 0; $i < $results->length; $i++) {
            $ret[$i] = $results->item($i);
        }

        return $ret;
    }

    /**
     * Output a node to text
     *
     * @param DOMElement $node  an XML element.
     * @return string
     */
    public static function printXML($node) {

        $dom = new DOMDocument();
        $cloned = $node->cloneNode(TRUE);
        $dom->appendChild( $dom->importNode($cloned,TRUE) );
        return($dom->saveHTML());
    }

    /**
     * parse and check an RST request response
     *
     * @param string $rst_response a SOAP response for an RST Request
     * @param string $messageId the request message id
     * @return string of SAML2 Assertion found in the response
     */
    public static function parseRSTRequestResponse($rst_response, $messageId) {

        try {
            $dom = new DOMDocument();
            if (!$dom->loadXML($rst_response)) {
                throw new Exception('Not a SOAP response.');
            }
            $relatesTo = sspmod_authigovt_Utils::xpQuery($dom->firstChild, '/soap:Envelope/soap:Header/wsa:RelatesTo');
            // print("name: ".$relatesTo[0]->nodeName."\n");
            if (empty($relatesTo)) {
                throw new Exception("Cannot find RelateTo element - cannot verify response: ".sspmod_authigovt_Utils::printXML($dom->firstChild));
            }
            $relatesTo = $relatesTo[0]->nodeValue;
            if ($relatesTo != $messageId) {
                throw new Exception("RelatesTo does not equal sent messageId: ".$relatesTo." - ".$messageId);
            }

            // is this a request?
            $samlresponse = sspmod_authigovt_Utils::xpQuery($dom->firstChild, '/soap:Envelope/soap:Body/wst:RequestSecurityTokenResponseCollection/wst:RequestSecurityTokenResponse/wst:RequestedSecurityToken/*[1]');
            if (empty($samlresponse)) {
                // is this a redeem ?
                $samlresponse = sspmod_authigovt_Utils::xpQuery($dom->firstChild, '/soap:Envelope/soap:Body/wst:RequestSecurityTokenResponse/wst:RequestedSecurityToken/*[1]');
            }

            if (empty($samlresponse)) {
                throw new Exception('Could not find Assertion in RST response: '.sspmod_authigovt_Utils::printXML($dom->firstChild));
            }

            // save the assertion snippet because the assertion checks are destructive
            $assertion = sspmod_authigovt_Utils::printXML($samlresponse[0]);

            // do the standard assertion tests
            $samlAssertion = new SAML2_Assertion($samlresponse[0]);

            SimpleSAML_Logger::debug("Valid RequestSecurityToken received from iCMS");
            return $assertion;
        }
        catch (Exception $e) {
            throw new Exception('Did not receive a valid RST response: '.$e->getMessage());
        }
    }


    /**
     * Sign and Send a SOAP request
     *
     * @param string $authsource Auth source to get the SP partner metadata config from
     * @param string $destination SOAP request destination URL
     * @param string $request The SOAP request message to sign and send
     * @param string $action The SOAP action to perform
     * @return string of XML SOAP response document
     */
    public static function signAndSend($authsource, $destination, $request, $action)  {

        // get our local SP entity config
        $source = SimpleSAML_Auth_Source::getById($authsource);
        $spMetadata = $source->getMetadata();
        $moduleConfig = SimpleSAML_Configuration::getConfig('module_igovt.php');

        // load the document and find all the nodes for signing
        $dom = new DOMDocument();
        $dom->loadXML($request);
        $root = $dom->childNodes->item(0);
        $issuerNodes = array();
        $issuerNodes = array_merge($issuerNodes, sspmod_authigovt_Utils::xpQuery($root, '/soap:Envelope/soap:Body'));
        $issuerNodes = array_merge($issuerNodes, sspmod_authigovt_Utils::xpQuery($root, '/soap:Envelope/soap:Header/wsa:To'));
        $issuerNodes = array_merge($issuerNodes, sspmod_authigovt_Utils::xpQuery($root, '/soap:Envelope/soap:Header/wsa:ReplyTo'));
        $issuerNodes = array_merge($issuerNodes, sspmod_authigovt_Utils::xpQuery($root, '/soap:Envelope/soap:Header/wsa:MessageID'));
        $issuerNodes = array_merge($issuerNodes, sspmod_authigovt_Utils::xpQuery($root, '/soap:Envelope/soap:Header/wsa:Action'));
        $issuerNodes = array_merge($issuerNodes, sspmod_authigovt_Utils::xpQuery($root, '/soap:Envelope/soap:Header/wsse:Security/wsu:Timestamp'));

        // load the keys for signing and putting the thumprint on
        $keyArray = SimpleSAML_Utilities::loadPrivateKey($spMetadata, TRUE);
        $certArray = SimpleSAML_Utilities::loadPublicKey($spMetadata, FALSE);
        $privateKey = new XMLSecurityKey(XMLSecurityKey::RSA_SHA1, array('type' => 'private'));
        if (array_key_exists('password', $keyArray)) {
            $privateKey->passphrase = $keyArray['password'];
        }
        $privateKey->loadKey($keyArray['PEM'], FALSE);

        // sign and thumbprint the SOAP request
        $objXMLSecDSig = new sspmod_authigovt_XMLSecurityDSigExtended();
        $objXMLSecDSig->setCanonicalMethod(XMLSecurityDSig::EXC_C14N);
        $objXMLSecDSig->addReferenceList(
            $issuerNodes,
            XMLSecurityDSig::SHA256,
            // array('http://www.w3.org/2000/09/xmldsig#enveloped-signature', XMLSecurityDSig::EXC_C14N),
            array(XMLSecurityDSig::EXC_C14N),
            array('ID' => FALSE, 'overwrite' => FALSE, 'prefix' => 'wsu', 'prefix_ns' => 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd')
        );
        $objXMLSecDSig->sign($privateKey);
        $objXMLSecDSig->addThumbprint($certArray['PEM'], TRUE);
        $signNodes = sspmod_authigovt_Utils::xpQuery($root, '/soap:Envelope/soap:Header/wsse:Security');
        $objXMLSecDSig->appendSignature($signNodes[0]);

        // output the document so that we can send the SOAP request
        $request = $dom->saveXML($dom);

        // figure out the keys and certifcates for mutual SSL interaction
        $issuer = $spMetadata->getString('entityid');
        $ctxOpts = array(
                        'http' => array('ignore_errors' => true,
                                        'timeout' => sspmod_authigovt_Utils::ICMS_CALL_TIMEOUT,
                                        'protocol_version' => 1.0,
                                        'header' => "Connection: close\r\nTE: compress, deflate, gzip\r\n",),
                        'https' => array('ignore_errors' => true,
                                         'timeout' => sspmod_authigovt_Utils::ICMS_CALL_TIMEOUT,
                                         'protocol_version' => 1.0,
                                         'header' => "Connection: close\r\nTE: compress, deflate, gzip\r\n",),
                        'ssl' => array(
                                        'capture_peer_cert' => TRUE,
                        ),
        );
        if ($spMetadata->hasValue('saml.SOAPClient.certificate')) {
            $cert = $spMetadata->getValue('saml.SOAPClient.certificate');
            if ($cert !== FALSE) {
                $ctxOpts['ssl']['local_cert'] = SimpleSAML_Utilities::resolveCert($spMetadata->getString('saml.SOAPClient.certificate'));
                if ($spMetadata->hasValue('saml.SOAPClient.privatekey_pass')) {
                    $ctxOpts['ssl']['passphrase'] = $spMetadata->getString('saml.SOAPClient.privatekey_pass');
                }
            }
        } else {
            /* Use the SP certificate and privatekey if it is configured. */
            $privateKey = SimpleSAML_Utilities::loadPrivateKey($spMetadata);
            $publicKey = SimpleSAML_Utilities::loadPublicKey($spMetadata);
            if ($privateKey !== NULL && $publicKey !== NULL && isset($publicKey['PEM'])) {
                $keyCertData = $privateKey['PEM'] . $publicKey['PEM'];
                $file = SimpleSAML_Utilities::getTempDir() . '/' . sha1($keyCertData) . '.pem';
                if (!file_exists($file)) {
                    SimpleSAML_Utilities::writeFile($file, $keyCertData);
                }
                $ctxOpts['ssl']['local_cert'] = $file;
                if (isset($privateKey['password'])) {
                    $ctxOpts['ssl']['passphrase'] = $privateKey['password'];
                }
            }
        }

        // do peer certificate verification
        $peerCertFile = SimpleSAML_Utilities::resolveCert($moduleConfig->getValue('iCMS.peer.certificate'));
        // old options
        $ctxOpts['ssl']['verify_depth'] = 1;
        $ctxOpts['ssl']['cafile'] = $peerCertFile;
        if ($moduleConfig->getValue('iCMS.verify')) {
            $ctxOpts['ssl']['verify_peer'] = TRUE;
        }
        else {
            $ctxOpts['ssl']['verify_peer'] = FALSE;
            $ctxOpts['ssl']['allow_self_signed'] = true; // just for testing XXX
        }
        SimpleSAML_Logger::debug('ssl parameters: '.var_export($ctxOpts, true));

        // $client = new SoapClient(NULL, $options);
        // do we use Curl or not - use Curl for the Proxy options mainly
        $config = SimpleSAML_Configuration::getInstance();
        $usecurl = $config->getBoolean('use_curl', NULL);
        // build SOAP call client and options
        $options = array(
            'trace' => 1,
            'uri' => $issuer,
            'location' => $destination,
        );
        if ($usecurl) {
            $client = new SOAPClientCurl(NULL, $options, $ctxOpts);
        }
        else {
            // create the streaming context for the SOAP call
            $context = stream_context_create($ctxOpts);
            if ($context === NULL) {
                throw new Exception('Unable to create SSL stream context');
            }
            $options['stream_context'] = $context;

            $client = new SoapClient(NULL, $options);
        }

        SimpleSAML_Utilities::debugMessage($request, 'out');
        SimpleSAML_Logger::debug("Action: ".$action);
        SimpleSAML_Logger::debug("Destination: ".$destination);
        // file_put_contents('/tmp/rst-request.xml', $request);

        /* Perform SOAP Request over HTTP */
        $soapresponsexml = $client->__doRequest($request, $destination, $action, sspmod_authigovt_Utils::SOAP_VERSION12);

        SimpleSAML_Logger::debug("response: ".$soapresponsexml);
        SimpleSAML_Logger::debug("last request: ".var_export($client->__getLastRequest(), true));
        SimpleSAML_Logger::debug("last response: ".var_export($client->__getLastResponse(), true));
        SimpleSAML_Logger::debug("last response headers: ".var_export($client->__getLastResponseHeaders(), true));
        // file_put_contents('/tmp/rst-response.txt', var_export(array($client->__getLastResponseHeaders(), $soapresponsexml), true));

        // $url_parts = parse_url($destination);
        // $host = $url_parts['host'];
        // SimpleSAML_Logger::debug("Host: ".$host);
        // $ctxOpts['http'] = array('ignore_errors' => true,
        //                                 'timeout' => sspmod_authigovt_Utils::ICMS_CALL_TIMEOUT,
        //                                 'protocol_version' => 1.0,
        //                                 //'header' => "Connection: close\r\nTE: compress, deflate, gzip\r\n",),
        //                                 'method' => 'POST',
        //                                 'content' => $request,
        //                                 'header' => "Content-Length: ".strlen($request)."\r\nHost: ".$host."\r\nSoapAction: ".$action."\r\nUser-Agent: PHP-SOAP-MINE\r\nContent-Type: application/soap+xml; charset=utf-8\r\nConnection: close\r\nTE: compress, deflate, gzip\r\n",);
        // $ctxOpts['https'] = array('ignore_errors' => true,
        //                                  'timeout' => sspmod_authigovt_Utils::ICMS_CALL_TIMEOUT,
        //                                  'protocol_version' => 1.0,
        //                                  //'header' => "Connection: close\r\nTE: compress, deflate, gzip\r\n",),
        //                                 'method' => 'POST',
        //                                 'content' => $request,
        //                                 'header' => "Content-Length: ".strlen($request)."\r\nHost: ".$host."\r\nSoapAction: ".$action."\r\nUser-Agent: PHP-SOAP-MINE\r\nContent-Type: application/soap+xml; charset=utf-8\r\nConnection: close\r\nTE: compress, deflate, gzip\r\n",);
        // $context = stream_context_create($ctxOpts);
        // $result = file_get_contents($destination, false, $context);
        // SimpleSAML_Logger::debug("result: ".$result);


        // check SOAP response
        if ($soapresponsexml === NULL || $soapresponsexml === "") {
            throw new Exception('Empty SOAP response, check peer certificate.');
        }
        SimpleSAML_Utilities::debugMessage($soapresponsexml, 'in');

        // Convert to SAML2_Message (DOMElement)
        $dom = new DOMDocument();
        if (!$dom->loadXML($soapresponsexml)) {
            throw new Exception('Not a SOAP response.');
        }

        $soapfault = sspmod_authigovt_Utils::getSOAPFault($dom);
        if (isset($soapfault)) {
            throw new Exception($soapfault);
        }

        return $soapresponsexml;
    }

    /**
     * Make an RST Token Request
     *
     * @param string $authsource Auth source to get the SP partner metadata config from
     * @param string $partner The partner that the Opaque Token Request is for
     * @param string $destination SOAP request destination URL
     * @param string $assertion SAML assertion to embed
     * @return string of XML SOAP request document - signed
     */
    public static function makeRSTRequest($authsource, $partner, $destination, $assertion)  {
        assert('is_string($authsource)');
        assert('is_string($partner)');
        assert('is_string($destination)');

        // build request skeleton
        $messageId = XMLSecurityDSig::generate_GUID();
        $request = '<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">'.
                   '<soap:Header><Action xmlns="http://www.w3.org/2005/08/addressing" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue</Action>'.
                   '<MessageID xmlns="http://www.w3.org/2005/08/addressing" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">'.
                   $messageId.'</MessageID>'.
                   '<To xmlns="http://www.w3.org/2005/08/addressing" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">'.
                   $destination.'</To>'.
                   '<ReplyTo xmlns="http://www.w3.org/2005/08/addressing" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">'.
                   '<Address>http://www.w3.org/2005/08/addressing/anonymous</Address></ReplyTo>'.
                   '<wsse:Security soap:mustUnderstand="true" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">'.
                   '<wsu:Timestamp><wsu:Created>'.gmdate("Y-m-d\TH:i:s\Z", time() + 0).'</wsu:Created><wsu:Expires>'.gmdate("Y-m-d\TH:i:s\Z", time() + 300).'</wsu:Expires></wsu:Timestamp>'.
                   '</wsse:Security>'.
                   '</soap:Header>'.
                   '<soap:Body xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">'.
                   '<wst:RequestSecurityToken xmlns:wst="'.sspmod_authigovt_Utils::NS_WST.'">'.
                   '<wst:RequestType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue</wst:RequestType>'.
                   '<wsp:AppliesTo xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy"><wsa:EndpointReference xmlns:wsa="http://www.w3.org/2005/08/addressing">'.
                   '<wsa:Address>'.$partner.'</wsa:Address></wsa:EndpointReference></wsp:AppliesTo>'.
                   '<wst:Claims Dialect="urn:nzl:govt:ict:stds:authn:deployment:igovt:gls:iCMS:1_0" xmlns:wst="'.sspmod_authigovt_Utils::NS_WST.'">'.
                   '<iCMS:Consent xmlns:iCMS="urn:nzl:govt:ict:stds:authn:deployment:igovt:gls:iCMS:1_0">urn:oasis:names:tc:SAML:2.0:consent:current-explicit</iCMS:Consent>'.
                   '<iCMS:TokenSubType xmlns:iCMS="urn:nzl:govt:ict:stds:authn:deployment:igovt:gls:iCMS:1_0">urn:nzl:govt:ict:stds:authn:deployment:igovt:gls:iCMS:1_0:SAMLV2.0:Authenticated</iCMS:TokenSubType>'.
                   '</wst:Claims><wst:TokenType>http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0</wst:TokenType>'.
                   '<ActAs xmlns="http://docs.oasis-open.org/ws-sx/ws-trust/200802">'.$assertion.'</ActAs>'.
                   '</wst:RequestSecurityToken></soap:Body></soap:Envelope>';


        $response = sspmod_authigovt_Utils::signAndSend($authsource, $destination, $request, sspmod_authigovt_Utils::RST_ISSUE);

        //Extract the SAML Security Token message from the response
        $samlresponse = sspmod_authigovt_Utils::parseRSTRequestResponse($response, $messageId);

        SimpleSAML_Logger::debug("Valid RequestSecurityToken request response received from iCMS");
        return $samlresponse;
    }

    /**
     * Make an RST Token Request type Seamless
     *
     * @param string $authsource Auth source to get the SP partner metadata config from
     * @param string $partner The partner that the Opaque Token Request is for
     * @param string $destination SOAP request destination URL
     * @param string $assertion SAML assertion to embed
     * @return string of XML SOAP request document - signed
     */
    public static function makeRSTRequestSeamless($authsource, $partner, $destination, $assertion)  {
        assert('is_string($authsource)');
        assert('is_string($partner)');
        assert('is_string($destination)');

        // build request skeleton - only difference is SubType - Seamless
        SimpleSAML_Logger::debug("Seamless request to iCMS for: ".$partner." destination: ".$destination);
        $messageId = XMLSecurityDSig::generate_GUID();
        $request = '<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">'.
                   '<soap:Header><Action xmlns="http://www.w3.org/2005/08/addressing" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue</Action>'.
                   '<MessageID xmlns="http://www.w3.org/2005/08/addressing" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">'.
                   $messageId.'</MessageID>'.
                   '<To xmlns="http://www.w3.org/2005/08/addressing" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">'.
                   $destination.'</To>'.
                   '<ReplyTo xmlns="http://www.w3.org/2005/08/addressing" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">'.
                   '<Address>http://www.w3.org/2005/08/addressing/anonymous</Address></ReplyTo>'.
                   '<wsse:Security soap:mustUnderstand="true" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">'.
                   '<wsu:Timestamp><wsu:Created>'.gmdate("Y-m-d\TH:i:s\Z", time() + 0).'</wsu:Created><wsu:Expires>'.gmdate("Y-m-d\TH:i:s\Z", time() + 300).'</wsu:Expires></wsu:Timestamp>'.
                   '</wsse:Security>'.
                   '</soap:Header>'.
                   '<soap:Body xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">'.
                   '<wst:RequestSecurityToken xmlns:wst="'.sspmod_authigovt_Utils::NS_WST.'">'.
                   '<wst:RequestType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue</wst:RequestType>'.
                   '<wsp:AppliesTo xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy"><wsa:EndpointReference xmlns:wsa="http://www.w3.org/2005/08/addressing">'.
                   '<wsa:Address>'.$partner.'</wsa:Address></wsa:EndpointReference></wsp:AppliesTo>'.
                   '<wst:Claims Dialect="urn:nzl:govt:ict:stds:authn:deployment:igovt:gls:iCMS:1_0" xmlns:wst="'.sspmod_authigovt_Utils::NS_WST.'">'.
                   '<iCMS:Consent xmlns:iCMS="urn:nzl:govt:ict:stds:authn:deployment:igovt:gls:iCMS:1_0">urn:oasis:names:tc:SAML:2.0:consent:current-explicit</iCMS:Consent>'.
                   '<iCMS:TokenSubType xmlns:iCMS="urn:nzl:govt:ict:stds:authn:deployment:igovt:gls:iCMS:1_0">urn:nzl:govt:ict:stds:authn:deployment:igovt:gls:iCMS:1_0:SAMLV2.0:Seamless</iCMS:TokenSubType>'.
                   '</wst:Claims><wst:TokenType>http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0</wst:TokenType>'.
                   '<ActAs xmlns="http://docs.oasis-open.org/ws-sx/ws-trust/200802">'.$assertion.'</ActAs>'.
                   '</wst:RequestSecurityToken></soap:Body></soap:Envelope>';


        $response = sspmod_authigovt_Utils::signAndSend($authsource, $destination, $request, sspmod_authigovt_Utils::RST_ISSUE);

        //Extract the SAML Security Token message from the response
        $samlresponse = sspmod_authigovt_Utils::parseRSTRequestResponse($response, $messageId);

        SimpleSAML_Logger::debug("Valid RequestSecurityToken request response received from iCMS");
        return $samlresponse;
    }

    /**
     * Make an RST Token Redeem Request
     *
     * @param string $authsource Auth source to get the SP partner metadata config from
     * @param string $destination SOAP request destination URL
     * @param string $assertion SAML assertion to embed
     * @return string of XML SOAP request document - signed
     */
    public static function makeRSTRedeemRequest($authsource, $destination, $assertion)  {
        assert('is_string($authsource)');
        assert('is_string($destination)');

        // build request skeleton
        $messageId = XMLSecurityDSig::generate_GUID();
        $request = '<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">'.
                   '<soap:Header><Action xmlns="http://www.w3.org/2005/08/addressing" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Validate</Action>'.
                   '<MessageID xmlns="http://www.w3.org/2005/08/addressing" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">'.
                   $messageId.'</MessageID>'.
                   '<To xmlns="http://www.w3.org/2005/08/addressing" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">'.
                   $destination.'</To>'.
                   '<ReplyTo xmlns="http://www.w3.org/2005/08/addressing" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">'.
                   '<Address>http://www.w3.org/2005/08/addressing/anonymous</Address></ReplyTo>'.
                   '<wsse:Security soap:mustUnderstand="true" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">'.
                   '<wsu:Timestamp><wsu:Created>'.gmdate("Y-m-d\TH:i:s\Z", time() + 0).'</wsu:Created><wsu:Expires>'.gmdate("Y-m-d\TH:i:s\Z", time() + 300).'</wsu:Expires></wsu:Timestamp>'.
                   '</wsse:Security>'.
                   '</soap:Header>'.
                   '<soap:Body xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">'.
                   '<wst:RequestSecurityToken xmlns:wst="'.sspmod_authigovt_Utils::NS_WST.'">'.
                   '<wst:RequestType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Validate</wst:RequestType>'.
                   '<wst:TokenType>http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0</wst:TokenType>'.
                   '<wst:ValidateTarget>'.
                   $assertion.
                   '</wst:ValidateTarget>'.
                   '<iCMS:AllowCreateFLT xmlns:iCMS="urn:nzl:govt:ict:stds:authn:deployment:igovt:gls:iCMS:1_0"/>'.
                   '</wst:RequestSecurityToken></soap:Body></soap:Envelope>';

        $response = sspmod_authigovt_Utils::signAndSend($authsource, $destination, $request, sspmod_authigovt_Utils::RST_VALIDATE);

        //Extract the SAML Security Token message from the response
        $samlresponse = sspmod_authigovt_Utils::parseRSTRequestResponse($response, $messageId);

        SimpleSAML_Logger::debug("Valid RequestSecurityToken Redeem response received from iCMS");

        // pass back the assertion object
        $dom = new DOMDocument();
        $dom->loadXML($samlresponse);
        $samlAssertion = new SAML2_Assertion($dom->firstChild);

        return $samlAssertion;
    }


    /*
     * Extracts the SOAP Fault from SOAP message
     * @param $soapmessage Soap response needs to be type DOMDocument
     * @return $soapfaultstring string|NULL
     */
    public static function getSOAPFault($soapmessage) {

        $soapfault = SAML2_Utils::xpQuery($soapmessage->firstChild, '/soap-env:Envelope/soap-env:Body/soap-env:Fault');

        if (empty($soapfault)) {
            /* No fault. */
            return NULL;
        }
        $soapfaultelement = $soapfault[0];
        $soapfaultstring = "Unknown fault string found"; // There is a fault element but we havn't found out what the fault string is
        // find out the fault string
        $faultstringelement =   SAML2_Utils::xpQuery($soapfaultelement, './soap-env:faultstring') ;
        if (!empty($faultstringelement)) {
            return $faultstringelement[0]->textContent;
        }
        return $soapfaultstring;
    }
}

