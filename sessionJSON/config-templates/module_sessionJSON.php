<?php
/*
 * Configuration for the sessionJSON module.
 *
 */

$config = array (
    // attributes to return from the given session ID
    'session.attributes' => array('uid'),
    // private_api_key that the web service user must present
    'API.Token' => array('blahblahblah' => 'AVS'),
    // No replay of the session lookup request allowed
    // this stops possible replay attacks
    'No.Replay' => true,
    // restricted subnets/IP addresses
    'Restricted.Subnets' => array('127.0.0.1/32'),
);

