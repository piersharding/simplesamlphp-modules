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
 *
 * template for the linking of iGOvt FLT to existing LDAP user
 */
 
$this->data['header'] = $this->t('{authigovt:authigovt:link_header}');

$this->includeAtTemplateBase('includes/header.php');
?>

<div class="form">
<?php
$params = array(
	'%IGOVTID%' => '<code>' . htmlspecialchars($this->data['igovtid']) . '</code>',
    '%USER%' => '<code>' . htmlspecialchars($this->data['username']) . '</code>',
	);
echo('<p>' . $this->t('{authigovt:authigovt:confirm_question}', $params) . '</p>');
?>
<form method="post" action="?">
<input type="hidden" name="AuthState" value="<?php echo htmlspecialchars($this->data['AuthState']); ?>" />

<input type="submit" name="ConfirmYes" value="<?php echo($this->t('{authigovt:authigovt:confirm}')); ?>" />
<input type="submit" name="ConfirmNo" value="<?php echo($this->t('{authigovt:authigovt:notconfirm}')); ?>" />

</form>
</div>

<?php
$this->includeAtTemplateBase('includes/footer.php');
?>