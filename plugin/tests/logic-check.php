<?php
// Checks the plugin's pure logic on real PHP with minimal WordPress stand-ins (no WordPress needed).
// Run: docker run --rm -v "$PWD/plugin:/p:ro" php:7.4-cli php /p/tests/logic-check.php
define( 'ABSPATH', '/site/' );
$GLOBALS['wp_version'] = '7.1.4';
$GLOBALS['transients'] = array();
$GLOBALS['requests'] = 0;
class WP_Error {}
function wp_json_encode( $d, $f = 0 ) { return json_encode( $d, $f ); }
function wp_normalize_path( $p ) { return str_replace( '\\', '/', $p ); }
function get_transient( $k ) { return isset( $GLOBALS['transients'][ $k ] ) ? $GLOBALS['transients'][ $k ][0] : false; }
function set_transient( $k, $v, $ttl ) { $GLOBALS['transients'][ $k ] = array( $v, $ttl ); }
function get_locale() { return 'en_US'; }
function add_query_arg( $a, $u ) { return $u . '?' . http_build_query( $a ); }
function wp_remote_get( $u, $o ) { $GLOBALS['requests']++; $GLOBALS['timeouts'][] = $o['timeout']; return new WP_Error(); }
function is_wp_error( $r ) { return $r instanceof WP_Error; }
require '/p/protect-reporter/includes/class-protect-reporter-inventory.php';
require '/p/protect-reporter/includes/class-protect-reporter-checks.php';

$fail = 0;
function check( $name, $ok ) { global $fail; echo ( $ok ? 'ok   ' : 'FAIL ' ) . $name . "\n"; if ( ! $ok ) { $fail++; } }
function call( $class, $method, $args ) { $m = new ReflectionMethod( $class, $method ); $m->setAccessible( true ); return $m->invokeArgs( null, $args ); }

// Fix 2: odd file names are encoded, ordinary ones untouched.
check( 'normal path unchanged', 'wp-content/uploads/a.php' === Protect_Reporter_Inventory::safe_path( 'wp-content/uploads/a.php' ) );
check( 'backslash encoded', 'wp-content/uploads/a%5Cb.php' === Protect_Reporter_Inventory::safe_path( "wp-content/uploads/a\\b.php" ) );
check( 'newline encoded', 'wp-content/uploads/a%0Ab.php' === Protect_Reporter_Inventory::safe_path( "wp-content/uploads/a\nb.php" ) );
check( 'utf-8 kept', 'wp-content/uploads/café.php' === Protect_Reporter_Inventory::safe_path( 'wp-content/uploads/café.php' ) );
check( 'site_relative encodes', 'wp-content/mu-plugins/x%09y.php' === Protect_Reporter_Inventory::site_relative( "/site/wp-content/mu-plugins/x\ty.php" ) );
check( 'outside root still null', null === Protect_Reporter_Inventory::site_relative( '/home/u/x.php' ) );
$list = array();
call( 'Protect_Reporter_Checks', 'add', array( &$list, str_repeat( 'a', 450 ) . '.php' ) );
check( 'long path kept, cut to 400', 1 === count( $list ) && 400 === strlen( $list[0] ) );

// Fix 4: big reports shrink, small ones are left alone, at least one example stays.
$paths = array();
for ( $i = 0; $i < 500; $i++ ) { $paths[] = 'wp-content/plugins/big/' . str_repeat( 'x', 300 ) . $i . '.php'; }
$payload = array( 'schema' => 1, 'checks' => array(
	'core' => array( 'status' => 'mismatch', 'modified' => $paths, 'unexpected' => $paths ),
	'plugins' => array( array( 'slug' => 'big', 'status' => 'mismatch', 'modified' => $paths ) ),
	'uploads_php' => $paths, 'mu_plugins_present' => array( 'wp-content/mu-plugins/a.php' ), 'user_ini' => array(),
	'recent_php_changes' => array_slice( $paths, 0, 50 ),
) );
check( 'test payload is over the limit', strlen( json_encode( $payload, JSON_UNESCAPED_SLASHES ) ) > 200000 );
$fitted = Protect_Reporter_Inventory::fit( $payload, 200000 );
check( 'fitted payload under 200 KB', strlen( json_encode( $fitted, JSON_UNESCAPED_SLASHES ) ) <= 200000 );
check( 'statuses kept', 'mismatch' === $fitted['checks']['core']['status'] && 'mismatch' === $fitted['checks']['plugins'][0]['status'] );
check( 'at least one example kept', count( $fitted['checks']['uploads_php'] ) >= 1 && count( $fitted['checks']['plugins'][0]['modified'] ) >= 1 );
check( 'mu-plugin list untouched', $payload['checks']['mu_plugins_present'] === $fitted['checks']['mu_plugins_present'] );
$small = array( 'checks' => array( 'uploads_php' => array( 'a' ) ) );
check( 'small payload unchanged', $small === Protect_Reporter_Inventory::fit( $small, 200000 ) );
$tiny = Protect_Reporter_Inventory::fit( $payload, 1000 );
check( 'never below one example', 1 === count( $tiny['checks']['uploads_php'] ) );

// Fix 3: a failed lookup is remembered, so wordpress.org being down costs one request.
call( 'Protect_Reporter_Checks', 'plugin_checksums', array( 'akismet', '5.3' ) );
call( 'Protect_Reporter_Checks', 'plugin_checksums', array( 'akismet', '5.3' ) );
check( 'plugin lookup failure: one request in a run', 1 === $GLOBALS['requests'] );
$m = new ReflectionProperty( 'Protect_Reporter_Checks', 'memo' ); $m->setAccessible( true ); $m->setValue( null, array() ); // next run
check( 'next run answers from the 1-hour memory', 'error' === call( 'Protect_Reporter_Checks', 'plugin_checksums', array( 'akismet', '5.3' ) ) && 1 === $GLOBALS['requests'] );
$t = $GLOBALS['transients'][ 'protect_reporter_psums_' . md5( 'akismet|5.3' ) ];
check( 'failure remembered for one hour', 'error' === $t[0] && 3600 === $t[1] );
check( 'cache-only makes no request', 'error' === call( 'Protect_Reporter_Checks', 'plugin_checksums', array( 'other', '1.0', true ) ) && 1 === $GLOBALS['requests'] );
call( 'Protect_Reporter_Checks', 'core_checksums', array() );
call( 'Protect_Reporter_Checks', 'core_checksums', array() );
check( 'core lookup failure: one request', 2 === $GLOBALS['requests'] );
check( 'requests use a 5 s timeout', array( 5 ) === array_values( array_unique( $GLOBALS['timeouts'] ) ) );

echo $fail ? "$fail FAILED\n" : "all passed\n";
exit( $fail ? 1 : 0 );
