<?php
/**
 * Ed25519 key pair and request signing (DESIGN.md §4.2).
 *
 * The private key never leaves this site. The platform stores only the public key, so a
 * breach of the platform can't be used to forge reports.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Protect_Reporter_Signer {

	const OPTION = 'protect_reporter_keypair';

	/** A fresh key pair (raw bytes). Saved only after enrollment succeeds. */
	public static function generate() {
		return sodium_crypto_sign_keypair();
	}

	public static function save( $keypair ) {
		update_option( self::OPTION, base64_encode( $keypair ), false ); // not autoloaded
	}

	public static function load() {
		$stored = get_option( self::OPTION );
		if ( ! is_string( $stored ) || '' === $stored ) {
			return null;
		}
		$raw = base64_decode( $stored, true );
		return ( false === $raw || SODIUM_CRYPTO_SIGN_KEYPAIRBYTES !== strlen( $raw ) ) ? null : $raw;
	}

	public static function public_key_b64( $keypair ) {
		return base64_encode( sodium_crypto_sign_publickey( $keypair ) );
	}

	/** First 16 hex chars of sha256(raw public key); the platform computes the same. */
	public static function key_id( $keypair ) {
		return substr( hash( 'sha256', sodium_crypto_sign_publickey( $keypair ) ), 0, 16 );
	}

	/**
	 * Headers for a signed request. Signs "<timestamp>\n<nonce>\n<sha256 hex of body>".
	 *
	 * @return array<string, string>
	 */
	public static function headers( $keypair, $body, $with_key_id = true ) {
		$timestamp = (string) time();
		$nonce     = bin2hex( random_bytes( 16 ) );
		$message   = $timestamp . "\n" . $nonce . "\n" . hash( 'sha256', $body );
		$signature = sodium_crypto_sign_detached( $message, sodium_crypto_sign_secretkey( $keypair ) );

		$headers = array(
			'Content-Type'        => 'application/json',
			'X-Protect-Timestamp' => $timestamp,
			'X-Protect-Nonce'     => $nonce,
			'X-Protect-Signature' => base64_encode( $signature ),
		);
		if ( $with_key_id ) {
			$headers['X-Protect-Key'] = self::key_id( $keypair );
		}
		return $headers;
	}
}
