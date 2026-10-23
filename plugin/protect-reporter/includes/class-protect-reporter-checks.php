<?php
/**
 * File checks for warning signs of tampering (DESIGN.md §4.12).
 *
 * Everything runs on this site. Only results leave it: site-relative paths and statuses,
 * never file contents. Official fingerprints come from api.wordpress.org and
 * downloads.wordpress.org, and they are only compared against, never executed (rule R12).
 *
 * Cheap hosts kill long requests, so a scan works in batches with a time budget and keeps a
 * cursor between runs. A new scan starts at most every few hours.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Protect_Reporter_Checks {

	const STATE        = 'protect_reporter_scan';   // scan in progress
	const RESULT       = 'protect_reporter_checks'; // last finished scan
	const BUDGET       = 10.0;                       // seconds per run
	const RESCAN_AFTER = 10800;                      // 3 hours
	const MAX_PATHS    = 500;
	const MAX_RECENT   = 50;
	const CACHE_TTL    = 86400;

	private static $php_ext = array( 'php', 'phtml', 'phar', 'php3', 'php4', 'php5', 'php7', 'php8', 'pht', 'phps' );

	/** @var float */
	private static $deadline = 0.0;

	// --- Public API -------------------------------------------------------------------

	/**
	 * Continue (or start) a scan for at most $budget seconds. $fresh starts a new scan now
	 * instead of waiting for RESCAN_AFTER (used by "Report now", e.g. after cleaning a site).
	 */
	public static function run( $budget = self::BUDGET, $fresh = false ) {
		self::$deadline = microtime( true ) + $budget;
		$state          = get_option( self::STATE );
		if ( ! is_array( $state ) ) {
			$last = get_option( self::RESULT );
			if ( ! $fresh && is_array( $last ) && isset( $last['finished_ts'] ) && time() - (int) $last['finished_ts'] < self::RESCAN_AFTER ) {
				return; // recent enough
			}
			$state = self::fresh_state( is_array( $last ) && isset( $last['finished_ts'] ) ? (int) $last['finished_ts'] : 0 );
		}

		if ( ! $state['core_done'] ) {
			self::step_core( $state );
		}
		if ( $state['core_done'] ) {
			self::step_walk( $state );
		}

		if ( $state['core_done'] && empty( $state['queue'] ) ) {
			self::finish( $state );
		} else {
			update_option( self::STATE, $state, false );
		}
	}

	/**
	 * The "checks" section of the report: the last finished scan, plus two cheap live checks.
	 */
	public static function report_section() {
		$last    = get_option( self::RESULT );
		$prepend = (string) ini_get( 'auto_prepend_file' );
		$section = array(
			'core'               => array(
				'status'     => 'unavailable',
				'modified'   => array(),
				'unexpected' => array(),
			),
			'plugins'            => array(),
			'uploads_php'        => array(),
			'mu_plugins_present' => self::mu_plugins_present(),
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
		if ( is_array( $last ) ) {
			foreach ( array( 'core', 'plugins', 'uploads_php', 'user_ini', 'recent_php_changes' ) as $key ) {
				if ( isset( $last[ $key ] ) ) {
					$section[ $key ] = $last[ $key ];
				}
			}
			$section['scan'] = array(
				'complete'    => true,
				'finished_at' => gmdate( 'Y-m-d\TH:i:s\Z', (int) $last['finished_ts'] ),
			);
		}
		return $section;
	}

	// --- Scan steps ---------------------------------------------------------------------

	/**
	 * @param int $since When the previous scan finished. PHP files changed after it are reported
	 *                   as a hint; the very first scan is the baseline and reports none.
	 */
	private static function fresh_state( $since ) {
		$root  = rtrim( wp_normalize_path( ABSPATH ), '/' );
		$queue = array();
		foreach ( array( 'wp-admin', 'wp-includes', 'wp-content/plugins', 'wp-content/themes', 'wp-content/uploads', 'wp-content/mu-plugins' ) as $dir ) {
			if ( is_dir( $root . '/' . $dir ) ) {
				$queue[] = array( $dir, 0 );
			}
		}
		return array(
			'since'       => $since,
			'core_done'   => false,
			'core_cursor' => 0,
			'queue'       => $queue,
			'user_ini'    => self::top_level_user_ini( $root ),
			'results'     => array(
				'core_status'     => 'unavailable',
				'core_modified'   => array(),
				'core_unexpected' => array(),
				'plugin_modified' => array(),
				'uploads_php'     => array(),
				'recent'          => array(),
			),
		);
	}

	/** Compare WordPress core files with the official checksums. */
	private static function step_core( &$state ) {
		$sums = self::core_checksums();
		if ( null === $sums ) {
			$state['results']['core_status'] = 'unavailable';
			$state['core_done']              = true;
			return;
		}
		$root  = rtrim( wp_normalize_path( ABSPATH ), '/' ) . '/';
		$paths = array_keys( $sums );
		$count = count( $paths );
		for ( $i = (int) $state['core_cursor']; $i < $count; $i++ ) {
			if ( self::out_of_time() ) {
				$state['core_cursor'] = $i;
				return;
			}
			$rel = $paths[ $i ];
			if ( 0 === strpos( $rel, 'wp-content/' ) ) {
				continue; // bundled themes/plugins are often removed on purpose
			}
			$file = $root . $rel;
			if ( is_file( $file ) && md5_file( $file ) !== $sums[ $rel ] ) {
				self::add( $state['results']['core_modified'], $rel );
			}
		}
		$state['results']['core_status'] = 'ok';
		$state['core_done']              = true;
	}

	/** Walk the directories in the queue, a batch at a time. */
	private static function step_walk( &$state ) {
		$root      = rtrim( wp_normalize_path( ABSPATH ), '/' );
		$core_sums = self::core_checksums();
		$plugins   = self::plugin_versions();
		$recent    = (int) $state['since'];

		while ( ! empty( $state['queue'] ) ) {
			list( $dir, $offset ) = array_shift( $state['queue'] );
			$entries              = @scandir( $root . '/' . $dir ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
			if ( false === $entries ) {
				continue;
			}
			$entries = array_values( array_diff( $entries, array( '.', '..' ) ) );
			$total   = count( $entries );
			for ( $i = (int) $offset; $i < $total; $i++ ) {
				if ( self::out_of_time() ) {
					array_unshift( $state['queue'], array( $dir, $i ) );
					return;
				}
				$name = $entries[ $i ];
				$rel  = $dir . '/' . $name;
				$abs  = $root . '/' . $rel;
				if ( is_link( $abs ) ) {
					continue;
				}
				if ( is_dir( $abs ) ) {
					if ( ! in_array( $name, array( '.git', 'node_modules' ), true ) ) {
						$state['queue'][] = array( $rel, 0 );
					}
					continue;
				}
				self::check_file( $state, $rel, $abs, $name, $core_sums, $plugins, $recent );
			}
		}
	}

	private static function check_file( &$state, $rel, $abs, $name, $core_sums, $plugins, $recent ) {
		$r = &$state['results'];
		if ( '.user.ini' === $name ) {
			self::add( $state['user_ini'], $rel );
			return;
		}
		$ext    = strtolower( pathinfo( $name, PATHINFO_EXTENSION ) );
		$is_php = in_array( $ext, self::$php_ext, true );

		// Core folders: anything PHP that WordPress doesn't ship is unexpected.
		if ( 0 === strpos( $rel, 'wp-admin/' ) || 0 === strpos( $rel, 'wp-includes/' ) ) {
			if ( $is_php && is_array( $core_sums ) && ! isset( $core_sums[ $rel ] ) ) {
				self::add( $r['core_unexpected'], $rel );
			}
			return;
		}

		// Uploads should hold media, not code.
		if ( 0 === strpos( $rel, 'wp-content/uploads/' ) ) {
			if ( $is_php && ! self::is_silence_placeholder( $abs, $name ) ) {
				self::add( $r['uploads_php'], $rel );
			}
			return;
		}

		// Plugins from wordpress.org: compare with their official checksums.
		if ( 0 === strpos( $rel, 'wp-content/plugins/' ) ) {
			$parts = explode( '/', substr( $rel, strlen( 'wp-content/plugins/' ) ), 2 );
			if ( 2 === count( $parts ) && isset( $plugins[ $parts[0] ] ) ) {
				$sums = self::plugin_checksums( $parts[0], $plugins[ $parts[0] ] );
				if ( is_array( $sums ) ) {
					if ( isset( $sums[ $parts[1] ] ) ) {
						if ( ! in_array( md5_file( $abs ), $sums[ $parts[1] ], true ) ) {
							self::add( $r['plugin_modified'], $rel );
						}
					} elseif ( $is_php ) {
						self::add( $r['plugin_modified'], $rel ); // PHP file the release doesn't have
					}
					return; // verified against checksums: no need for the mtime hint
				}
			}
		}

		// Everything else (themes, premium plugins, mu-plugins): PHP changed since the last scan
		// is a hint, not proof. Updates cause it too.
		if ( $recent > 0 && $is_php && ! self::is_silence_placeholder( $abs, $name ) && @filemtime( $abs ) > $recent ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			if ( count( $r['recent'] ) < self::MAX_RECENT ) {
				self::add( $r['recent'], $rel );
			}
		}
	}

	private static function finish( $state ) {
		$r         = $state['results'];
		$plugins   = array();
		$versions  = self::plugin_versions();
		$by_plugin = array();
		foreach ( $r['plugin_modified'] as $path ) {
			$slug                 = explode( '/', substr( $path, strlen( 'wp-content/plugins/' ) ) )[0];
			$by_plugin[ $slug ][] = $path;
		}
		foreach ( $versions as $slug => $version ) {
			$sums = self::plugin_checksums( $slug, $version );
			if ( is_array( $sums ) ) {
				$status = empty( $by_plugin[ $slug ] ) ? 'ok' : 'mismatch';
			} else {
				$status = 'none' === $sums ? 'unverifiable' : 'unavailable';
			}
			$plugins[] = array(
				'slug'     => $slug,
				'status'   => $status,
				'modified' => isset( $by_plugin[ $slug ] ) ? array_slice( $by_plugin[ $slug ], 0, self::MAX_PATHS ) : array(),
			);
		}

		$core_status = $r['core_status'];
		if ( 'ok' === $core_status && ( ! empty( $r['core_modified'] ) || ! empty( $r['core_unexpected'] ) ) ) {
			$core_status = 'mismatch';
		}
		update_option(
			self::RESULT,
			array(
				'finished_ts'        => time(),
				'core'               => array(
					'status'     => $core_status,
					'modified'   => $r['core_modified'],
					'unexpected' => $r['core_unexpected'],
				),
				'plugins'            => array_slice( $plugins, 0, self::MAX_PATHS ),
				'uploads_php'        => $r['uploads_php'],
				'user_ini'           => $state['user_ini'],
				'recent_php_changes' => $r['recent'],
			),
			false
		);
		delete_option( self::STATE );
	}

	// --- Official checksums (read-only reference data from wordpress.org) ----------------

	/** @return array<string,string>|null  path => md5 */
	private static function core_checksums() {
		global $wp_version;
		$locale = get_locale();
		$key    = 'protect_reporter_core_sums_' . md5( $wp_version . '|' . $locale );
		$cached = get_transient( $key );
		if ( is_array( $cached ) ) {
			return $cached;
		}
		foreach ( array_unique( array( $locale, 'en_US' ) ) as $try ) {
			$url  = add_query_arg(
				array(
					'version' => $wp_version,
					'locale'  => $try,
				),
				'https://api.wordpress.org/core/checksums/1.0/'
			);
			$data = self::fetch_json( $url );
			if ( isset( $data['checksums'] ) && is_array( $data['checksums'] ) && ! empty( $data['checksums'] ) ) {
				$sums = array();
				foreach ( $data['checksums'] as $path => $md5 ) {
					if ( is_string( $path ) && is_string( $md5 ) ) {
						$sums[ $path ] = strtolower( $md5 );
					}
				}
				set_transient( $key, $sums, self::CACHE_TTL );
				return $sums;
			}
		}
		return null;
	}

	/**
	 * @return array<string,string[]>|string  path => accepted md5s, or 'none' (not on
	 *                                         wordpress.org) or 'error' (couldn't check).
	 */
	private static function plugin_checksums( $slug, $version ) {
		if ( ! preg_match( '/^[a-z0-9][a-z0-9._-]{0,99}$/', $slug ) || ! preg_match( '/^[0-9A-Za-z.+~_-]{1,64}$/', (string) $version ) ) {
			return 'none';
		}
		$key    = 'protect_reporter_psums_' . md5( $slug . '|' . $version );
		$cached = get_transient( $key );
		if ( false !== $cached ) {
			return $cached;
		}
		$url      = 'https://downloads.wordpress.org/plugin-checksums/' . rawurlencode( $slug ) . '/' . rawurlencode( $version ) . '.json';
		$response = wp_remote_get( $url, array( 'timeout' => 10, 'redirection' => 2 ) );
		if ( is_wp_error( $response ) ) {
			return 'error';
		}
		$code = (int) wp_remote_retrieve_response_code( $response );
		if ( 404 === $code ) {
			set_transient( $key, 'none', self::CACHE_TTL );
			return 'none';
		}
		$data = 200 === $code ? json_decode( wp_remote_retrieve_body( $response ), true ) : null;
		if ( ! isset( $data['files'] ) || ! is_array( $data['files'] ) ) {
			return 'error';
		}
		$sums = array();
		foreach ( $data['files'] as $path => $info ) {
			if ( is_string( $path ) && isset( $info['md5'] ) ) {
				$sums[ $path ] = array_map( 'strtolower', array_filter( (array) $info['md5'], 'is_string' ) );
			}
		}
		set_transient( $key, $sums, self::CACHE_TTL );
		return $sums;
	}

	/** Reference data from api.wordpress.org only. The platform's replies are never read. */
	private static function fetch_json( $url ) {
		if ( 0 !== strpos( $url, 'https://api.wordpress.org/' ) ) {
			return null;
		}
		$response = wp_remote_get( $url, array( 'timeout' => 10, 'redirection' => 2 ) );
		if ( is_wp_error( $response ) || 200 !== (int) wp_remote_retrieve_response_code( $response ) ) {
			return null;
		}
		$data = json_decode( wp_remote_retrieve_body( $response ), true );
		return is_array( $data ) ? $data : null;
	}

	// --- Helpers -------------------------------------------------------------------------

	private static function out_of_time() {
		return microtime( true ) > self::$deadline;
	}

	private static function add( &$list, $path ) {
		if ( count( $list ) < self::MAX_PATHS && strlen( $path ) <= 400 ) {
			$list[] = $path;
		}
	}

	/** Plugins that live in their own folder, with their versions (slug => version). */
	private static function plugin_versions() {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		$out = array();
		foreach ( get_plugins() as $file => $data ) {
			$dir = dirname( $file );
			if ( '.' !== $dir && ! empty( $data['Version'] ) ) {
				$out[ strtolower( $dir ) ] = (string) $data['Version'];
			}
		}
		return $out;
	}

	/**
	 * The classic empty "Silence is golden" index.php that WordPress and many plugins drop
	 * into folders. Read locally to recognise it; its content is never sent.
	 */
	private static function is_silence_placeholder( $abs, $name ) {
		if ( 'index.php' !== strtolower( $name ) || @filesize( $abs ) > 200 ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			return false;
		}
		$content = (string) @file_get_contents( $abs ); // phpcs:ignore WordPress.PHP.NoSilencedErrors, WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
		return (bool) preg_match( '~^\s*<\?php\s*(//|#|/\*+)?\s*silence is golden\.?\s*(\*+/)?\s*(\?>)?\s*$~i', $content )
			|| (bool) preg_match( '~^\s*<\?php\s*$~', $content );
	}

	private static function mu_plugins_present() {
		$out = array();
		foreach ( Protect_Reporter_Inventory::mu_plugin_files() as $path ) {
			$out[] = $path;
		}
		return $out;
	}

	private static function top_level_user_ini( $root ) {
		$found = array();
		foreach ( array( '.user.ini', 'wp-content/.user.ini' ) as $rel ) {
			if ( is_file( $root . '/' . $rel ) ) {
				$found[] = $rel;
			}
		}
		return $found;
	}

	private static function location( $path ) {
		$relative = Protect_Reporter_Inventory::site_relative( $path );
		return null === $relative ? 'outside_site_root' : $relative;
	}
}
