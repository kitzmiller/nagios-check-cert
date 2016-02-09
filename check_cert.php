#!/usr/bin/php
<?php

/******************************************************************************
check_cert.php - ckitzmiller@hampshire.edu
******************************************************************************/

$shortopts = "H:p:w:c:";
$longopts = array();
$options = getopt($shortopts, $longopts);
$dateformat = "Y-m-d H:i:s";

if(!isset($options["H"])) { usage(); }
if(!isset($options["p"])) { $options["p"] = 443; } //default to 443
if(!isset($options["w"])) { $options["w"] = 2592000; } //default to 30 days
if(!isset($options["c"])) { $options["c"] = 0; } //default to 0 days

$hostname = $options["H"];
$port = $options["p"];
$warning = $options["w"];
$critical = $options["c"];

switch($port) {
	case  21: $starttls = "-starttls ftp"; break;
	case  25: $starttls = "-starttls smtp"; break;
	case 110: $starttls = "-starttls pop3"; break;
	case 143: $starttls = "-starttls imap"; break;
	default: $starttls = "";
}

$execstring = "echo | openssl s_client -showcerts -connect $hostname:$port $starttls 2>/dev/null";
$lastline = exec($execstring, $output, $returnvalue);
if($returnvalue) {
	echo("UNKNOWN: Error running openssl s_client: $lastline\n");
	exit(3);
}

if(!sizeof($output)) {
	echo("UNKNOWN: No output from $hostname:$port\n");
	exit(3);
}

$certs = array();
$cert = "";
$copy = false;
for($i = 0; $line = $output[$i]; $i++) {
	if(strstr($line, "BEGIN CERTIFICATE")) { $copy = true; }
	if($copy) { $cert .= $line . "\n"; }
	if(strstr($line, "END CERTIFICATE")) {
		$certs[] = openssl_x509_parse($cert);
		$cert = "";
		$copy = false;
	}
}

$warn = false;
$crit = false;
$nextexpire = $certs[0]["validTo_time_t"];
$retvals = array();
foreach($certs as $cert) {
	$now = time();
	if($cert["validFrom_time_t"] > $now) {
		$crit = true;
		$retvals[] = "CN: " . $cert["subject"]["CN"] . " not yet valid";
	}
	if(($cert["validTo_time_t"] - $now) < $critical) {
		$crit = true;
		$retvals[] = "CN: " . $cert["subject"]["CN"] . " expires " . date($dateformat, $cert["validTo_time_t"]);
	} else if(($cert["validTo_time_t"] - $now) < $warning) {
		$warn = true;
		$retvals[] = "CN: " . $cert["subject"]["CN"] . " expires " . date($dateformat, $cert["validTo_time_t"]);
	}
	if($cert["validTo_time_t"] <= $nextexpire) {
		$nextexpire = $cert["validTo_time_t"];
		$okval = "CN: " . $cert["subject"]["CN"] . " expires " . date($dateformat, $nextexpire);
		$perfdata = "seconds_until_expiration=" . ($nextexpire - $now) . "s;$warning;$critical";
	}
}

if(!$warn && !$crit) {
	$retvals[] = $okval;
}
$retcode = 0;
if($warn) { $retcode = 1; }
if($crit) { $retcode = 2; }

echo(implode("; ", $retvals) . "|" . $perfdata . "\n");
exit($retcode);

function usage() {
	echo("Usage:\n\tcheck_ssl_cert -H <Host> [-p <port>] [-w <SecondsTillWarn>] [-c <SecondsTillCritical>]\n");
	echo("\n");
	echo("This script will check an SSL/TLS connection to verify the validity of the\n");
	echo("certificates used in the connection. If any certificates in the certificate\n");
	echo("chain are invalid then the script will return an error. If any certificate is\n");
	echo("nearing its expiration date then a warning will be issued.\n");
	echo("\n");
	echo("Note: If ports 21, 25, 110, or 143 is specified then starttls is assumed.\n");
	exit(3);
}
?>
