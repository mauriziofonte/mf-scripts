<?php

/**
 * CP-PHP-Backup-Trigger
 * PHP script to allow periodic cPanel backups automatically, optionally to a remote FTP server.
 *
 * @version 1.0 - Last edited on 25 February 2018
 * @author Maurizio Fonte <fonte.maurizio@gmail.com>
 *
 * @attention: This script contains passwords. KEEP ACCESS TO THIS FILE SECURE! (place it in your home dir, or anywhere NOT publicly available via a virtualhost)
 */

/* 
	CONFIG
	Edit this params to make the system correctly connect to:
	1) Your cPanel account -- CPANEL_ variables
	2) Your remote FTP/SSH server -- BACKUP_ variables
	3) The behaviour of the script -- Verbosity, logging
*/
define ( 'CPANEL_USER', '' );													// your cPanel username
define ( 'CPANEL_PASS', '' );													// your cPanel password
define ( 'CPANEL_HOST', '' );													// the domain name of your cPanel hosting provider
define ( 'CPANEL_SSL', true );													// whether your cPanel hosting provider needs to be accessed via SSL (https) or not
define ( 'CPANEL_THEME', 'paper_lantern' );										// the theme you're actually using in your cPanel account
define ( 'BACKUP_FTP_USER', '' );												// the remote FTP/SSH username
define ( 'BACKUP_FTP_PASS', '' );												// the remote FTP/SSH password
define ( 'BACKUP_FTP_HOST', '' );												// the remote FTP/SSH server
define ( 'BACKUP_FTP_PORT', '' );												// the remote FTP/SSH port
define ( 'BACKUP_FTP_MODE', 'ftp' );											// the modality of which you want let cPanel connect to your remote server ( valid configs are scp | ftp | passiveftp )
define ( 'BACKUP_FTP_REMOTE_DIR', '/' );										// the remote directory where you want the backup file to be stored
define ( 'BACKUP_NOTIFY_EMAIL', '' );											// the notification email upon backup success ( triggered from cPanel ) -- NULL if you want to disable this
define ( 'VERBOSE_OUTPUT', true );												// whether you want or not verbosity of this script
define ( 'OUTPUT_LOG', rtrim ( dirname ( __FILE__ ), DIRECTORY_SEPARATOR ) . DIRECTORY_SEPARATOR . pathinfo ( __FILE__, PATHINFO_FILENAME ) . '.log' );
define ( 'COOKIE_JAR_FILE', rtrim ( dirname ( __FILE__ ), DIRECTORY_SEPARATOR ) . DIRECTORY_SEPARATOR . '.cpanel.temp.cookie' );
/*
	END CONFIG
	From now on, the script does not need any modification
*/

ini_set ( 'max_execution_time', 120 );

$cpanel_url = ( CPANEL_SSL ) ? 'https://' . CPANEL_HOST . ':2083' : 'http://' . CPANEL_HOST . ':2082';
define ( 'CPANEL_FULL_URL', $cpanel_url );

// check stage
if ( ! function_exists ( 'curl_init' ) ) die ( 'Your PHP environment does not have support for Curl functions. Contact your hosting provider. Exiting now...' . chr(10) );
if ( ! function_exists ( 'ftp_connect' ) ) die ( 'Your PHP environment does not have support for FTP functions. Contact your hosting provider. Exiting now...' . chr(10) );
if ( strtolower ( php_sapi_name () ) !== "cli" ) die ( 'You have to call this script from command line. Exiting now...' . chr(10) );
if ( ! file_put_contents ( COOKIE_JAR_FILE, 'TEMP' ) ) die ( 'This script needs write access to current directory ( ' . dirname ( __FILE__ ) . ' ). Double check your environment and retry...' . chr(10) );
touch ( COOKIE_JAR_FILE );
if ( ! empty ( OUTPUT_LOG ) && is_file ( OUTPUT_LOG ) ) unlink ( OUTPUT_LOG );

// stage 1. Check connection to FTP server provided, prior of triggering the automated backup via cPanel
if ( in_array ( BACKUP_FTP_MODE, Array ( 'ftp', 'passiveftp' ) ) && ! ftp_test () ) die ( 'Cannot connect to the remote FTP server you provided. Check configuration and credentials. Exiting now...' . chr(10) );
else if ( in_array ( BACKUP_FTP_MODE, Array ( 'scp' ) ) && ! ssh_test () ) die ( 'Cannot connect to the remote SSH server you provided. Check configuration and credentials. Exiting now...' . chr(10) );

// stage 2. Login Phase + Backup Trigger
if ( ( $security_token = cpanel_login () ) !== false ) {
	
	define ( 'CPANEL_LOGGED_IN_URL', CPANEL_FULL_URL . '/' . trim ( $security_token, '/' ) . '/' );
	
	if ( VERBOSE_OUTPUT ) out ( ' # LOG # successfully logged in into your cPanel hosting provider with security_token=' . trim ( $security_token, '/' ) );
	if ( VERBOSE_OUTPUT ) out ( ' # LOG # Going to trigger the automated FTP backup verbosely...' );
	
	$backup_trigger = exec_curl ( 
		CPANEL_LOGGED_IN_URL . 'frontend/' . CPANEL_THEME . '/backup/dofullbackup.html', 
		Array (
			'dest' => BACKUP_FTP_MODE,
			'email_radio' => ( BACKUP_NOTIFY_EMAIL ) ? '1' : '0',
			'email' => ( BACKUP_NOTIFY_EMAIL ) ? BACKUP_NOTIFY_EMAIL : '',
			'server' => BACKUP_FTP_HOST,
			'user' => BACKUP_FTP_USER,
			'pass' => BACKUP_FTP_PASS,
			'port' => BACKUP_FTP_PORT,
			'rdir' => BACKUP_FTP_REMOTE_DIR
		)
	);
	
	if ( $backup_trigger['status'] ) {
		
		// let's check the output from cPanel...
		$cpanel_backup_status = false;
		$cpanel_backup_message = 'Undefined message';
		if ( strpos ( $backup_trigger['response'], 'backupSuccess' ) !== false ) {
			$pos = strpos ( $backup_trigger['response'], '<div id="backupSuccessMsg"' );
			if ( $pos !== false ) {
				$msg = strip_tags ( substr ( $backup_trigger['response'], $pos, ( strpos ( $backup_trigger['response'], '</div>', $pos+1 ) - $pos ) ) );
				$cpanel_backup_status = true;
				$cpanel_backup_message = $msg;
			}
		}
		else if ( strpos ( $backup_trigger['response'], 'backupFailure' ) !== false ) {
			$pos = strpos ( $backup_trigger['response'], '<div id="backupFailureMsg"' );
			if ( $pos !== false ) {
				$msg = strip_tags ( substr ( $backup_trigger['response'], $pos, ( strpos ( $backup_trigger['response'], '</div>', $pos+1 ) - $pos ) ) );
				$cpanel_backup_message = $msg;
			}
		}
		
		if ( $cpanel_backup_status ) {
			out ( 'CPANEL BACKUP TRIGGERED CORRECTLY!' );
		}
		else {
			out ( '# CPANEL DOFULLBACKUP ERROR #' );
		}
		
		out ( 'Response from cPanel server: ' . trim ( preg_replace ( '/\s\s+/', ' ', str_replace ( Array ( chr(13).chr(10), chr(10), chr(9) ), ' ', $cpanel_backup_message ) ) ) );
	}
	else out ( '# CPANEL DOFULLBACKUP ERROR #. Cannot reliably get a response from the /backup/dofullbackup realm of cPanel. This can be a problem on the hosting provider itself.' );
	
}
else out ( '# CPANEL LOGIN ERROR #. Cannot login with the credentials provided. Also, make sure the CPANEL url you configured ( ' . CPANEL_FULL_URL . ' ) does exist and is reachable via a browser.' );

// finalize
unlink ( COOKIE_JAR_FILE );

function out ( $message ) {
	echo $message . chr(10);
	if ( ! empty ( OUTPUT_LOG ) ) file_put_contents ( OUTPUT_LOG, date ( 'Y-m-d H:i:s' ) . chr(9) . $message . chr(10), FILE_APPEND );
}

function exec_curl ( $url, $post_vars = Array () ) {
	
	if ( VERBOSE_OUTPUT ) out ( ' # LOG # Going to call remote url with cUrl: ' . $url . ' ( post_vars=' . serialize ( $post_vars ) . ' )' );
	
	$ch = curl_init();
	curl_setopt($ch, CURLOPT_URL,            $url);
	curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
	curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
	curl_setopt($ch, CURLOPT_USERAGENT,      'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:58.0) Gecko/20100101 Firefox/58.0' );
	curl_setopt($ch, CURLOPT_REFERER,        CPANEL_FULL_URL );
	if ( ! empty ( $post_vars ) && is_array ( $post_vars ) && count ( array_keys ( $post_vars ) ) > 0 ) {
		curl_setopt($ch, CURLOPT_POST,       true);
		curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query ( $post_vars ));
	}
	curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 20);
	curl_setopt($ch, CURLOPT_TIMEOUT,        1200);
	curl_setopt($ch, CURLOPT_COOKIEJAR,      COOKIE_JAR_FILE );
	curl_setopt($ch, CURLOPT_COOKIEFILE,     COOKIE_JAR_FILE );
	
	$result = curl_exec($ch);
	$httpcode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
	
	if ( VERBOSE_OUTPUT ) out ( ' # LOG # cUrl response http_code=' . $http_code . '. Response_length=' . strlen ( $result ) );
	
	curl_close($ch);
	if ( $httpcode === 200 ) return Array ( 'status' => true, 'response' => $result );
	else return Array ( 'status' => false, 'response' => $result );
}

function cpanel_login ( ) {
	
	if ( VERBOSE_OUTPUT ) out ( ' # LOG # Going to initiate login phase with your cPanel hosting provider...' );
	
	$login = exec_curl ( CPANEL_FULL_URL . '/login/?login_only=1', Array ( 'goto_uri' => '/', 'user' => CPANEL_USER, 'pass' => CPANEL_PASS ) );
	if ( $login['status'] && ( $decoded = json_decode ( $login['response'], true ) ) !== false && array_key_exists ( 'security_token', $decoded ) ) {
		return $decoded['security_token'];
	}
	else return false;
}

function ftp_test ( ) {
	
	if ( ! function_exists ( 'ftp_connect' ) ) {
		if ( VERBOSE_OUTPUT ) out ( ' # WARNING # ftp_test() : cannot reliably check if your FTP connection works because your PHP installation is lacking ftp functions support. Skipping this check...' );
		return true;
	}
	
	$conn_id = @ftp_connect ( BACKUP_FTP_HOST, BACKUP_FTP_PORT ); 
	$login_result = @ftp_login ( $conn_id, BACKUP_FTP_USER, BACKUP_FTP_PASS );

	// check connection and login result
	if ( ( !$conn_id ) || ( ! $login_result ) ) {
		ftp_close ( $conn_id );
		return false;
	} 
	else {
		
		if ( VERBOSE_OUTPUT ) out ( ' # LOG # connected to FTP remote server with CONN_ID=' . $conn_id . ', LOGIN_RES=' . $login_result );
		
		if ( BACKUP_FTP_MODE === 'passiveftp' ) ftp_pasv ( $conn_id, true );
		$contents = ftp_rawlist ( $conn_id, '/' );
		
		if ( VERBOSE_OUTPUT ) out ( ' # LOG # remote FTP directory contains ' . count ( array_keys ( $contents ) ) . ' items...' );
		
		ftp_close ( $conn_id );
		return true;
	}
}

function ssh_test ( ) {
	
	if ( ! function_exists ( 'ssh2_connect' ) ) {
		if ( VERBOSE_OUTPUT ) out ( ' # WARNING # ssh_test() : cannot reliably check if your SSH connection works because your PHP installation is lacking ssh2 functions support. Skipping this check...' );
		return true;
	}
	
	$conn = @ssh2_connect ( BACKUP_FTP_HOST, BACKUP_FTP_PORT );
	$res = @ssh2_auth_password ( $conn, BACKUP_FTP_USER, BACKUP_FTP_PASS );
	if ( ! $conn || ! $res ) return false;
	else return true;
}
