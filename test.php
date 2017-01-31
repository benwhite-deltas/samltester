<?php

require_once __DIR__.'/vendor/autoload.php';

class TestContainer extends SAML2\Compat\AbstractContainer {
	public function getLogger()
	{
		return new \Psr\Log\NullLogger();
	}

	/**
	 * Generate a random identifier for identifying SAML2 documents.
	 */
	public function generateId()
	{
		return mt_rand();
	}

	/**
	 * Log an incoming message to the debug log.
	 *
	 * Type can be either:
	 * - **in** XML received from third party
	 * - **out** XML that will be sent to third party
	 * - **encrypt** XML that is about to be encrypted
	 * - **decrypt** XML that was just decrypted
	 *
	 * @param string $message
	 * @param string $type
	 * @return void
	 */
	public function debugMessage($message, $type)
	{
		// TODO: Implement debugMessage() method.
	}

	/**
	 * Trigger the user to perform a GET to the given URL with the given data.
	 *
	 * @param string $url
	 * @param array $data
	 * @return void
	 */
	public function redirect($url, $data = array())
	{
		// TODO: Implement redirect() method.
	}

	/**
	 * Trigger the user to perform a POST to the given URL with the given data.
	 *
	 * @param string $url
	 * @param array $data
	 * @return void
	 */
	public function postRedirect($url, $data = array())
	{
		// TODO: Implement postRedirect() method.
	}
}

$certificate = <<<EOF
-----BEGIN CERTIFICATE-----
xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
-----END CERTIFICATE-----
EOF;
$key = <<<EOF
-----BEGIN PRIVATE KEY-----
xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
-----END PRIVATE KEY-----
EOF;

switch ($_SERVER['REQUEST_METHOD']) {
case 'GET':
	?><!doctype html><html><head></head><body>
<h1>Craft SAML Attributes</h1>
<form method="post" action="">
	<label ><span>EntityName</span>
		<input type="text" name="entityId" value=""/>
	</label>
	<br/>
	<label id="attributeName"><span>AttributeName</span>
		<input type="text" name="attributeName[]" value=""/>
	</label>
	<label id="attributeValue">><span>AttributeValue</span>
		<input type="text" name="attributeValue[]" value=""/>
	</label>
	<br/>
	<input type="submit" value="Submit"/>
</form>
</body></html><?php
	break;
case 'POST':

	\SAML2\Compat\ContainerSingleton::setContainer(new TestContainer());

	$attributes = array_combine($_POST['attributeName'], $_POST['attributeValue']);
	$targetEntityId = '';
	$acsUrl = '';
	$sourceEntityId = $_POST['entityId'];

	$a = new SAML2\Assertion();
	$keyObj = new RobRichards\XMLSecLibs\XMLSecurityKey(
		RobRichards\XMLSecLibs\XMLSecurityKey::RSA_SHA1,
		['type' => 'private']
	);
	$keyObj->loadKey($key);
	//$a->setSignatureKey($keyObj);
	//$a->setCertificates([$certificate]);
	$a->setIssuer($sourceEntityId);
	$a->setValidAudiences([$targetEntityId]);
	$now = time();
	$a->setNotBefore($now - 30);
	$a->setNotOnOrAfter($now + 600);
	$a->setAuthnContextClassRef(\SAML2\Constants::AC_PASSWORD);
	$a->setAuthnInstant($now);
	$a->setSessionNotOnOrAfter($now + (8 * 60 * 60));
	$a->setSessionIndex(sha1($now));

	$sc = new SAML2\XML\saml\SubjectConfirmation();
	$sc->SubjectConfirmationData = new SAML2\XML\saml\SubjectConfirmationData();
	$sc->SubjectConfirmationData->NotOnOrAfter = $now + 600;
	$sc->SubjectConfirmationData->Recipient = $acsUrl;
	$sc->Method = \SAML2\Constants::CM_BEARER;

	$a->setSubjectConfirmation([$sc]);

	$attrs = [];
	foreach ($attributes as $attributeName => $value) {
		$attrs[$attributeName] = [new SAML2\XML\saml\AttributeValue($value)];
	}

	$a->setAttributeNameFormat(\SAML2\Constants::NAMEFORMAT_UNSPECIFIED);
	$a->setAttributes($attrs);

	$nameId = new \SAML2\XML\saml\NameID();
	$nameId->Format = \SAML2\Constants::NAMEID_UNSPECIFIED;
	$nameId->value = (string)microtime(true);

	$a->setNameId([$nameId]);

	$r = new SAML2\Response();

	$r->setIssuer($sourceEntityId);
	$r->setDestination($acsUrl);

	$r->setSignatureKey($keyObj);
	$r->setCertificates([$certificate]);

	$r->setAssertions([$a]);

	$msgStr = $r->toSignedXML();
	$msgStr->ownerDocument->formatOutput = true;
	$msgStr = $msgStr->ownerDocument->saveXML($msgStr);

	?><!doctype html><html><head></head><body>
<pre><?= htmlentities($msgStr) ?></pre>
<form method="post" action="<?= $acsUrl ?>">
	<input type="hidden" name="SAMLResponse" value="<?= base64_encode($msgStr) ?>"/>
	<input type="submit" value="Submit"/>
</form>
</body></html>
<?php	break;
default:

}
