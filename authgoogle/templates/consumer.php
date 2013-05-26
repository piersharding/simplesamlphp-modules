<?php

$this->data['header'] = 'Google OpenID Login';
$this->data['autofocus'] = 'openid-identifier';
$this->includeAtTemplateBase('includes/header.php');

?>
<style>
input.openid-identifier {
   background: url(http://stat.livejournal.com/img/openid-inputicon.gif) no-repeat;
/*   background-color: #fff; */
	border-left: 1px solid #ccc;
	border-right: 1px solid #aaa;
	border-top: 1px solid #aaa;
	border-bottom: 1px solid #ccc;
	color: #555;
   background-position: 0 50%;
   padding-left: 18px;
}
fieldset {
	border-left: 1px solid #aaa;
	border-right: 1px solid #ccc;
	border-top: 1px solid #ccc;
	border-bottom: 1px solid #aaa;
	padding: 1em;
}
legend {
	padding-left: .3em;
	padding-right: .3em;
	color: #555;
}

div.error {
	padding: 1em; margin: 1em;
	background: red;
	color: white;
	border: 1px solid #600;
}
</style>


    <?php if (isset($this->data['error'])) { print "<div class=\"error\">" . $this->data['error'] . "</div>"; } ?>

<?php
$this->includeAtTemplateBase('includes/footer.php');
?>
