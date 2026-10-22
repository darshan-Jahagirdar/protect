<?php
/**
 * Builds the report payload. This is the complete, hard-coded data list (DESIGN.md §5.1).
 *
 * Only versions, settings and site-relative paths. Never contacts, visitors, logs,
 * database contents, file contents or credentials. Adding a field here means updating
 * DESIGN.md §5.1 and the platform schema (platform/app/api/schemas.py) as well.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Protect_Reporter_Inventory {

	const VERSION_RE = '/^[0-9A-Za-z.+~:_-]{1,64}$/';
	const TOKEN_RE   = '/^[a-z0-9][a-z0-9._-]{0,63}$/';
	const SLUG_RE    = '/^[a-z0-9][a-z0-9._-]{0,99}$/';

	/**
	 * @return array<string, mixed>
	 */
	public static function build() {
		return array(
			'schema'         => 1,
			'plugin_version' => PROTECT_REPORTER_VERSION,
			'generated_at'   => gmdate( 'Y-m-d\TH:i:s\Z' ),
			'site_url'       => get_site_url(),
			'php'            => self::php(),
			'libs'           => self::libs(),
			'wordpress'      => self::wordpress(),
			'plugins'        => self::plugins(),
			'mu_plugins'     => self::mu_plugins(),
			'themes'         => self::themes(),
			'db'             => self::db(),
			'server'         => array( 'software' => self::text( isset( $_SERVER['SERVER_SOFTWARE'] ) ? wp_unslash( $_SERVER['SERVER_SOFTWARE'] ) : null ) ), // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- sanitised by self::text().
			'os'             => self::os(),
			'checks'         => self::checks(),
		);
	}

	// --- Sections -------------------------------------------------------------------

	private static function php() {
		$extensions = array();
		foreach ( get_loaded_extensions() as $name ) {
			$token = self::token( str_replace( ' ', '-', $name ) );
			if ( null === $token || count( $extensions ) >= 200 ) {
				continue;
			}
			$extensions[] = array(
				'name'    => $token,
				'version' => self::version( phpversion( $name ) ),
			);
		}

		$ini = array();
		foreach ( array( 'session.upload_progress.enabled', 'memory_limit', 'opcache.enable', 'expose_php' ) as $key ) {
			$value       = ini_get( $key );
			$ini[ $key ] = false === $value ? null : self::text( $value );
		}

		return array(
			'version'    => PHP_VERSION,
			'major'      => PHP_MAJOR_VERSION,
			'minor'      => PHP_MINOR_VERSION,
			'release'    => PHP_RELEASE_VERSION,
			'extra'      => PHP_EXTRA_VERSION,
			'sapi'       => self::token( php_sapi_name() ),
			'extensions' => $extensions,
			'ini'        => $ini,
		);
	}

	private static function libs() {
		// Every key is always present, so this encodes as a JSON object even when all are null.
		$libs = array(
			'openssl'     => defined( 'OPENSSL_VERSION_TEXT' ) ? self::text( OPENSSL_VERSION_TEXT ) : null,
			'curl'        => null,
			'curl_ssl'    => null,
			'libxml2'     => defined( 'LIBXML_DOTTED_VERSION' ) ? self::text( LIBXML_DOTTED_VERSION ) : null,
			'pcre2'       => defined( 'PCRE_VERSION' ) ? self::text( PCRE_VERSION ) : null,
			'icu'         => defined( 'INTL_ICU_VERSION' ) ? self::text( INTL_ICU_VERSION ) : null,
			'imagemagick' => null,
		);
		if ( function_exists( 'curl_version' ) ) {
			$curl             = curl_version();
			$libs['curl']     = isset( $curl['version'] ) ? self::text( $curl['version'] ) : null;
			$libs['curl_ssl'] = isset( $curl['ssl_version'] ) ? self::text( $curl['ssl_version'] ) : null;
		}
		if ( class_exists( 'Imagick' ) ) {
			$im                  = Imagick::getVersion();
			$libs['imagemagick'] = isset( $im['versionString'] ) ? self::text( $im['versionString'] ) : null;
		}
		return $libs;
	}

	private static function wordpress() {
		$locale = get_locale();
		return array(
			'version'   => self::version( get_bloginfo( 'version' ) ),
			'multisite' => is_multisite(),
			'locale'    => preg_match( '/^[A-Za-z]{2,3}(?:_[A-Za-z0-9]{2,8}){0,2}$/', $locale ) ? $locale : 'en_US',
		);
	}

	private static function plugins() {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		$out = array();
		foreach ( get_plugins() as $file => $data ) {
			$slug = self::slug( '.' === dirname( $file ) ? basename( $file, '.php' ) : dirname( $file ) );
			if ( null === $slug || count( $out ) >= 500 ) {
				continue;
			}
			$out[] = array(
				'slug'    => $slug,
				'version' => self::version( isset( $data['Version'] ) ? $data['Version'] : null ),
				'active'  => is_plugin_active( $file ) || ( is_multisite() && is_plugin_active_for_network( $file ) ),
				'name'    => (string) self::text( isset( $data['Name'] ) ? $data['Name'] : '' ),
			);
		}
		return $out;
	}

	private static function mu_plugins() {
		if ( ! function_exists( 'get_mu_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		$out = array();
		foreach ( get_mu_plugins() as $file => $data ) {
			$path = self::site_relative( WPMU_PLUGIN_DIR . '/' . $file );
			if ( null === $path || count( $out ) >= 200 ) {
				continue;
			}
			$out[] = array(
				'file'    => $path,
				'name'    => (string) self::text( isset( $data['Name'] ) ? $data['Name'] : '' ),
				'version' => self::version( isset( $data['Version'] ) ? $data['Version'] : null ),
			);
		}
		return $out;
	}

	private static function themes() {
		$active   = get_stylesheet();
		$template = get_template();
		$out      = array();
		foreach ( wp_get_themes() as $stylesheet => $theme ) {
			$slug = self::slug( $stylesheet );
			if ( null === $slug || count( $out ) >= 200 ) {
				continue;
			}
			$out[] = array(
				'slug'    => $slug,
				'version' => self::version( $theme->get( 'Version' ) ),
				'active'  => $stylesheet === $active || $stylesheet === $template,
			);
		}
		return $out;
	}

	private static function db() {
		global $wpdb;
		if ( ! isset( $wpdb ) || ! method_exists( $wpdb, 'db_server_info' ) ) {
			return null;
		}
		$info = (string) $wpdb->db_server_info();
		return array(
			'engine'  => false !== stripos( $info, 'mariadb' ) ? 'mariadb' : ( '' === $info ? 'unknown' : 'mysql' ),
			'version' => self::version( $wpdb->db_version() ),
		);
	}

	private static function os() {
		// Read as a plain text file. Never a shell command. Silenced: open_basedir may block it.
		$raw = @file_get_contents( '/etc/os-release' ); // phpcs:ignore WordPress.PHP.NoSilencedErrors, WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
		if ( false === $raw ) {
			return null;
		}
		$fields = array();
		foreach ( preg_split( '/\r?\n/', $raw ) as $line ) {
			if ( preg_match( '/^([A-Z_]+)=(.*)$/', trim( $line ), $m ) ) {
				$fields[ $m[1] ] = trim( $m[2], " \t\"'" );
			}
		}
		$id_like = isset( $fields['ID_LIKE'] ) ? self::text( strtolower( $fields['ID_LIKE'] ) ) : null;
		return array(
			'id'          => isset( $fields['ID'] ) ? self::token( $fields['ID'] ) : null,
			'id_like'     => null === $id_like ? null : substr( $id_like, 0, 100 ),
			'version_id'  => isset( $fields['VERSION_ID'] ) ? self::version( $fields['VERSION_ID'] ) : null,
			'pretty_name' => isset( $fields['PRETTY_NAME'] ) ? self::text( $fields['PRETTY_NAME'] ) : null,
		);
	}

	/**
	 * File checks arrive in build step 10. Until then the report says honestly that they
	 * haven't run, apart from the two cheap settings-based checks.
	 */
	private static function checks() {
		$mu_present = array();
		foreach ( self::mu_plugins() as $mu ) {
			$mu_present[] = $mu['file'];
		}
		$prepend = (string) ini_get( 'auto_prepend_file' );
		return array(
			'core'               => array(
				'status'     => 'unavailable',
				'modified'   => array(),
				'unexpected' => array(),
			),
			'plugins'            => array(),
			'uploads_php'        => array(),
			'mu_plugins_present' => $mu_present,
			'user_ini'           => array(),
			'auto_prepend'       => array(
				'set'      => '' !== $prepend,
				'location' => '' === $prepend ? null : self::location( $prepend ),
			),
			'recent_php_changes' => array(),
			'scan'               => array(
				'complete'    => false,
				'finished_at' => null,
			),
		);
	}

	// --- Helpers that keep every value inside the platform's schema ---------------------

	/** Free text: no control characters, at most 200 characters. */
	private static function text( $value ) {
		if ( null === $value || false === $value ) {
			return null;
		}
		$clean = preg_replace( '/[\x00-\x1f\x7f]/', '', (string) $value );
		return substr( trim( $clean ), 0, 200 );
	}

	private static function version( $value ) {
		if ( ! is_string( $value ) ) {
			return null;
		}
		$value = trim( $value );
		return preg_match( self::VERSION_RE, $value ) ? $value : null;
	}

	private static function token( $value ) {
		$value = strtolower( trim( (string) $value ) );
		return preg_match( self::TOKEN_RE, $value ) ? $value : null;
	}

	private static function slug( $value ) {
		$value = strtolower( trim( (string) $value ) );
		$value = preg_replace( '/[^a-z0-9._-]+/', '-', $value );
		$value = substr( trim( $value, '-' ), 0, 100 );
		return preg_match( self::SLUG_RE, $value ) ? $value : null;
	}

	/**
	 * Path relative to the WordPress root, or null when it's outside it. Paths outside
	 * the site root are never sent: they can contain server usernames.
	 */
	public static function site_relative( $absolute ) {
		$root = rtrim( wp_normalize_path( ABSPATH ), '/' ) . '/';
		$path = wp_normalize_path( $absolute );
		if ( 0 !== strpos( $path, $root ) ) {
			return null;
		}
		$relative = substr( $path, strlen( $root ) );
		if ( '' === $relative || in_array( '..', explode( '/', $relative ), true ) ) {
			return null;
		}
		return substr( $relative, 0, 400 );
	}

	private static function location( $path ) {
		$relative = self::site_relative( $path );
		return null === $relative ? 'outside_site_root' : $relative;
	}
}
