<?php
/**
 * Sends enrollment and reports to the platform.
 *
 * Output only: from each reply we read the HTTP status code and nothing else (rule R2).
 * The reply body is never parsed, stored or acted on.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Protect_Reporter_Sender {

	const SETTINGS = 'protect_reporter_settings'; // platform_url, enrolled_at, key_id, site_url
	const LAST     = 'protect_reporter_last';     // last attempt, shown on the transparency page
	const CLI_CRON = 'protect_reporter_cli_cron'; // when cron last ran from the command line
	const MAX_BYTES = 200000;                     // the platform refuses bodies over 256 KB

	public static function settings() {
		$s = get_option( self::SETTINGS );
		return is_array( $s ) ? $s : array();
	}

	public static function platform_url() {
		$s = self::settings();
		return isset( $s['platform_url'] ) ? (string) $s['platform_url'] : '';
	}

	/**
	 * True when this site's address differs from the one it was connected with. That is most
	 * likely a copy, such as a staging clone, which copies the signing key along with the
	 * database. Reports are paused so a copy can never report as the live site (the platform
	 * refuses them too).
	 */
	public static function site_moved() {
		$s = self::settings();
		return ! empty( $s['site_url'] ) && untrailingslashit( get_site_url() ) !== $s['site_url'];
	}

	/**
	 * Plain HTTP is allowed only on local/development WordPress installs (the Docker demo).
	 */
	public static function valid_platform_url( $url ) {
		$parts = wp_parse_url( $url );
		if ( ! is_array( $parts ) || empty( $parts['host'] ) || empty( $parts['scheme'] ) ) {
			return false;
		}
		if ( 'https' === $parts['scheme'] ) {
			return true;
		}
		return 'http' === $parts['scheme'] && in_array( wp_get_environment_type(), array( 'local', 'development' ), true );
	}

	/**
	 * Enroll with a one-time code. Generates a new key pair and keeps it only on success.
	 *
	 * @return int HTTP status (204 = enrolled), or 0 if the request couldn't be sent.
	 */
	public static function enroll( $platform_url, $code ) {
		$keypair = Protect_Reporter_Signer::generate();
		$body    = wp_json_encode(
			array(
				'code'           => strtoupper( preg_replace( '/[^A-Za-z0-9-]/', '', $code ) ),
				'site_url'       => get_site_url(),
				'public_key'     => Protect_Reporter_Signer::public_key_b64( $keypair ),
				'plugin_version' => PROTECT_REPORTER_VERSION,
			),
			JSON_UNESCAPED_SLASHES
		);
		$status  = self::post( $platform_url, '/api/v1/enroll', $body, Protect_Reporter_Signer::headers( $keypair, $body, false ) );

		if ( 204 === $status ) {
			Protect_Reporter_Signer::save( $keypair );
			update_option(
				self::SETTINGS,
				array(
					'platform_url' => untrailingslashit( $platform_url ),
					'enrolled_at'  => gmdate( 'Y-m-d\TH:i:s\Z' ),
					'key_id'       => Protect_Reporter_Signer::key_id( $keypair ),
					'site_url'     => untrailingslashit( get_site_url() ),
				),
				false
			);
			delete_option( self::LAST );
		}
		return $status;
	}

	/**
	 * Build and send one report. Called by cron, after updates, and by "Report now".
	 *
	 * @param bool $fresh_scan Start a new file scan now ("Report now" does this).
	 * @return int HTTP status (204 = accepted), or 0 if nothing was sent.
	 */
	public static function send_report( $fresh_scan = false ) {
		// Only the web SAPI reports: a CLI PHP can be a different binary from the one
		// serving the site, so its versions would be misleading. The platform enforces this too.
		if ( 'cli' === php_sapi_name() ) {
			// Some hosts run WordPress's scheduled tasks this way, so the hourly report never goes
			// out. Remembered so the settings page can say so.
			update_option( self::CLI_CRON, time(), false );
			return 0;
		}
		$keypair = Protect_Reporter_Signer::load();
		$url     = self::platform_url();
		if ( null === $keypair || '' === $url || self::site_moved() ) {
			return 0;
		}

		Protect_Reporter_Checks::run( Protect_Reporter_Checks::BUDGET, (bool) $fresh_scan ); // within its time budget
		$payload = Protect_Reporter_Inventory::fit( Protect_Reporter_Inventory::build(), self::MAX_BYTES );
		$body    = wp_json_encode( $payload, JSON_UNESCAPED_SLASHES );
		$status  = self::post( $url, '/api/v1/report', $body, Protect_Reporter_Signer::headers( $keypair, $body ) );

		update_option(
			self::LAST,
			array(
				'at'      => gmdate( 'Y-m-d\TH:i:s\Z' ),
				'status'  => $status,
				'payload' => $body,
			),
			false
		);
		update_option( 'protect_reporter_last_php', PHP_VERSION, false );
		if ( 204 === $status ) {
			self::remember_site_url();
		}
		return $status;
	}

	/**
	 * Sites connected before the address check have no site_url saved. The platform accepts a
	 * report only from the address it enrolled, so after a 204 this address is the right one.
	 */
	private static function remember_site_url() {
		$s = self::settings();
		if ( empty( $s['site_url'] ) && ! empty( $s['key_id'] ) ) {
			$s['site_url'] = untrailingslashit( get_site_url() );
			update_option( self::SETTINGS, $s, false );
		}
	}

	private static function post( $platform_url, $path, $body, $headers ) {
		if ( ! self::valid_platform_url( $platform_url ) || ! is_string( $body ) ) {
			return 0;
		}
		$response = wp_remote_post(
			untrailingslashit( $platform_url ) . $path,
			array(
				'body'        => $body,
				'headers'     => $headers,
				'timeout'     => 15,
				'redirection' => 0,
				'sslverify'   => true,
			)
		);
		if ( is_wp_error( $response ) ) {
			return 0;
		}
		return (int) wp_remote_retrieve_response_code( $response ); // status only (rule R2)
	}
}
