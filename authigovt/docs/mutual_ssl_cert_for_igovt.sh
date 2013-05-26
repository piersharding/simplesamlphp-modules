#!/bin/sh

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# @package    SimpleSAMLphp
# @subpackage authigovt
# @author     Piers Harding
# @license    http://www.gnu.org/copyleft/gpl.html GNU GPL
# @copyright  (C) 2012-2013 and beyond Catalyst IT Ltd, and Piers Harding

# generate the key 
openssl req -newkey rsa:2048 -new -x509 -days 1095 -nodes -out ite_mutualssl_saml_sp.crt -keyout ite_mutualssl_saml_sp.pem

# create a new request 
openssl req -key ite_mutualssl_saml_sp.pem -new -x509 -days 1095 -nodes -out ite_mutualssl_saml_sp.req

# create self signed cert removing the V3 extensions 
openssl x509 -in ite_mutualssl_saml_sp.req -clrext -days 1095 -signkey ite_mutualssl_saml_sp.pem -out ite_mutualssl_saml_sp.crt

cat ite_mutualssl_saml_sp.crt ite_mutualssl_saml_sp.pem > ite_mutualssl_saml_sp.combined

openssl x509 -noout -text -in ite_mutualssl_saml_sp.crt
