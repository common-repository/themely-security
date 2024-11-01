<?php
/*
Plugin Name: Themely Security – Malware Prevention, Anti-Spam & Firewall
Description: WordPress Security, Malware Prevention, Anti-spam & Firewall. Super simple, install-and-forget, WordPress security plugin for everyone.
Version: 1.0.6
Author: Themely
Author URI: https://www.themely.com
License: GPLv2 or later
License URI: http://www.gnu.org/licenses/gpl-2.0.html
Text Domain: themely-security
Tested up to: 5.4.2
Requires PHP: 5.6
*/

/*
 * Plugin action links
 * https://codex.wordpress.org/Plugin_API/Filter_Reference/plugin_action_links_(plugin_file_name)
*/
function themely_security_action_links($links) {
   $links[] = '<a href="https://wordpress.org/support/plugin/themely-security/" target="_blank">Get help or report an issue</a>';
   $links[] = '<a href="https://wordpress.org/support/plugin/themely-security/reviews/#new-post" target="_blank">Review this plugin</a>';
   return $links;
}
add_filter( 'plugin_action_links_' . plugin_basename(__FILE__), 'themely_security_action_links' );

/*
 * Limit Login Attempts
 * https://phppot.com/wordpress/how-to-limit-login-attempts-in-wordpress/
*/
function themely_security_check_attempted_login($user, $username, $password) {
    if ( get_transient( 'attempted_login' ) ) {
        $datas = get_transient( 'attempted_login' );

        if ( $datas['tried'] >= 3 ) {
            $until = get_option( '_transient_timeout_' . 'attempted_login' );
            $time = themely_security_time_to_go($until);

            return new WP_Error( 'too_many_tried',  sprintf( __( '<strong>ERROR</strong>: You have reached the limit for login attempts, you may try again in %1$s.' ) , $time ) );
        }
    }
    return $user;
}
add_filter( 'authenticate', 'themely_security_check_attempted_login', 30, 3 );

function themely_security_login_failed($username) {
    if ( get_transient( 'attempted_login' ) ) {
        $datas = get_transient( 'attempted_login' );
        $datas['tried']++;

        if ( $datas['tried'] <= 3 )
            set_transient( 'attempted_login', $datas , 1800 );
    } else {
        $datas = array(
            'tried'     => 1
        );
        set_transient( 'attempted_login', $datas , 1800 );
    }
}
add_action( 'wp_login_failed', 'themely_security_login_failed', 10, 1 ); 

function themely_security_time_to_go($timestamp) {
    $periods = array(
        "second",
        "minute",
        "hour",
        "day",
        "week",
        "month",
        "year"
    );
    $lengths = array(
        "60",
        "60",
        "24",
        "7",
        "4.35",
        "12"
    );
    $current_timestamp = time();
    $difference = abs($current_timestamp - $timestamp);
    for ($i = 0; $difference >= $lengths[$i] && $i < count($lengths) - 1; $i ++) {
        $difference /= $lengths[$i];
    }
    $difference = round($difference);
    if (isset($difference)) {
        if ($difference != 1)
            $periods[$i] .= "s";
            $output = "$difference $periods[$i]";
            return $output;
    }
}

/*
 * Disable Pingbacks
 * https://forumweb.hosting/20044-how-to-protect-wordpress-from-xml-rpc-attacks.html#post-125651
*/
function themely_security_stop_pings($vectors) {
	unset( $vectors['pingback.ping'] );
	return $vectors;
}
add_filter( 'xmlrpc_methods', 'themely_security_stop_pings');

/*
 * htaccess rules
 * https://forumweb.hosting/20044-how-to-protect-wordpress-from-xml-rpc-attacks.html#post-125651
 * https://www.wpbeginner.com/wp-tutorials/9-most-useful-htaccess-tricks-for-wordpress/
 * https://www.wpexplorer.com/htaccess-wordpress-security/
 * https://www.geckoandfly.com/25102/htaccess-snippets-hardening-wordpress-security-hacking/
 * https://perishablepress.com/6g/
*/
// Add rules to htaccess on plugin activation
function themely_security_add_htaccess() {
    $htaccess_file = get_home_path() . '.htaccess';
    $rules = array('# Block xmlrpc.php
<files xmlrpc.php>
Order allow,deny
Deny from all
</files>
#Protect wp-config.php
<files wp-config.php>
order allow,deny
deny from all
</files>
# Disable directory browsing
Options All -Indexes
# Deny access to all .htaccess files
<files ~ "^.*\.([Hh][Tt][Aa])">
order allow,deny
deny from all
satisfy all
</files>
# Blocks some XSS attacks
<IfModule mod_rewrite.c>
RewriteCond %{QUERY_STRING} (\|%3E) [NC,OR]
RewriteCond %{QUERY_STRING} GLOBALS(=|\[|\%[0-9A-Z]{0,2}) [OR]
RewriteCond %{QUERY_STRING} _REQUEST(=|\[|\%[0-9A-Z]{0,2})
RewriteRule .* index.php [F,L]
</IfModule>
# Blocks all wp-includes folders and files
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteBase /
RewriteRule ^wp-admin/includes/ - [F,L]
RewriteRule !^wp-includes/ - [S=3]
RewriteRule ^wp-includes/[^/]+\.php$ - [F,L]
RewriteRule ^wp-includes/js/tinymce/langs/.+\.php - [F,L]
RewriteRule ^wp-includes/theme-compat/ - [F,L]
</IfModule>
# 6G FIREWALL/BLACKLIST
# 6G:[QUERY STRING]
<IfModule mod_rewrite.c>
	RewriteEngine On
	RewriteCond %{QUERY_STRING} (eval\() [NC,OR]
	RewriteCond %{QUERY_STRING} (127\.0\.0\.1) [NC,OR]
	RewriteCond %{QUERY_STRING} ([a-z0-9]{2000,}) [NC,OR]
	RewriteCond %{QUERY_STRING} (javascript:)(.*)(;) [NC,OR]
	RewriteCond %{QUERY_STRING} (base64_encode)(.*)(\() [NC,OR]
	RewriteCond %{QUERY_STRING} (GLOBALS|REQUEST)(=|\[|%) [NC,OR]
	RewriteCond %{QUERY_STRING} (<|%3C)(.*)script(.*)(>|%3) [NC,OR]
	RewriteCond %{QUERY_STRING} (\\|\.\.\.|\.\./|~|`|<|>|\|) [NC,OR]
	RewriteCond %{QUERY_STRING} (boot\.ini|etc/passwd|self/environ) [NC,OR]
	RewriteCond %{QUERY_STRING} (thumbs?(_editor|open)?|tim(thumb)?)\.php [NC,OR]
	RewriteCond %{QUERY_STRING} (\'|\")(.*)(drop|insert|md5|select|union) [NC]
	RewriteRule .* - [F]
</IfModule>
# 6G:[REQUEST METHOD]
<IfModule mod_rewrite.c>
	RewriteCond %{REQUEST_METHOD} ^(connect|debug|move|put|trace|track) [NC]
	RewriteRule .* - [F]
</IfModule>
# 6G:[REFERRER]
<IfModule mod_rewrite.c>
	RewriteCond %{HTTP_REFERER} ([a-z0-9]{2000,}) [NC,OR]
	RewriteCond %{HTTP_REFERER} (semalt.com|todaperfeita) [NC]
	RewriteRule .* - [F]
</IfModule>
# 6G:[REQUEST STRING]
<IfModule mod_alias.c>
	RedirectMatch 403 (?i)([a-z0-9]{2000,})
	RedirectMatch 403 (?i)(https?|ftp|php):/
	RedirectMatch 403 (?i)(base64_encode)(.*)(\()
	RedirectMatch 403 (?i)(=\\\'|=\\%27|/\\\'/?)\.
	RedirectMatch 403 (?i)/(\$(\&)?|\*|\"|\.|,|&|&amp;?)/?$
	RedirectMatch 403 (?i)(\{0\}|\(/\(|\.\.\.|\+\+\+|\\\"\\\")
	RedirectMatch 403 (?i)(~|`|<|>|:|;|,|%|\\|\{|\}|\[|\]|\|)
	RedirectMatch 403 (?i)/(=|\$&|_mm|cgi-|muieblack)
	RedirectMatch 403 (?i)(&pws=0|_vti_|\(null\)|\{\$itemURL\}|echo(.*)kae|etc/passwd|eval\(|self/environ)
	RedirectMatch 403 (?i)\.(aspx?|bash|bak?|cfg|cgi|dll|exe|git|hg|ini|jsp|log|mdb|out|sql|svn|swp|tar|rar|rdf)$
	RedirectMatch 403 (?i)/(^$|(wp-)?config|mobiquo|phpinfo|shell|sqlpatch|thumb|thumb_editor|thumbopen|timthumb|webshell)\.php
</IfModule>
# 6G:[USER AGENT]
<IfModule mod_setenvif.c>
	SetEnvIfNoCase User-Agent ([a-z0-9]{2000,}) bad_bot
	SetEnvIfNoCase User-Agent (archive.org|binlar|casper|checkpriv|choppy|clshttp|cmsworld|diavol|dotbot|extract|feedfinder|flicky|g00g1e|harvest|heritrix|httrack|kmccrew|loader|miner|nikto|nutch|planetwork|postrank|purebot|pycurl|python|seekerspider|siclab|skygrid|sqlmap|sucker|turnit|vikspider|winhttp|xxxyy|youda|zmeu|zune) bad_bot
	# Apache < 2.3
	<IfModule !mod_authz_core.c>
		Order Allow,Deny
		Allow from all
		Deny from env=bad_bot
	</IfModule>
	# Apache >= 2.3
	<IfModule mod_authz_core.c>
		<RequireAll>
			Require all Granted
			Require not env bad_bot
		</RequireAll>
	</IfModule>
</IfModule>',
    );
    return insert_with_markers($htaccess_file, 'Themely Security', $rules);
}
register_activation_hook(__FILE__, 'themely_security_add_htaccess');

/*
 * Remove rules from htaccess on plugin deactivation
*/
function themely_security_remove_htaccess() {
    $htaccess_file = get_home_path() . '.htaccess';
    return insert_with_markers($htaccess_file, 'Themely Security', '');
}
register_deactivation_hook(__FILE__, 'themely_security_remove_htaccess');

/*
 * Stop execution of scripts within your uploads directory
 * https://help.dreamhost.com/hc/en-us/articles/215525277-How-to-install-WordPress-using-the-One-Click-Installer%20(see%20at%20bottom)
*/
// Create htaccess on plugin activation
function themely_security_add_uploads_htaccess() {
    $uploads = wp_get_upload_dir();
    $htaccess_file = trailingslashit( $uploads['basedir'] ) . '.htaccess';
    $rules = array(
    	'SetHandler no-handler'
    );
    return insert_with_markers($htaccess_file, 'Themely Security', $rules);
}
register_activation_hook(__FILE__, 'themely_security_add_uploads_htaccess');

// Remove rules from htaccess on plugin deactivation
function themely_security_remove_uploads_htaccess() {
    $uploads = wp_get_upload_dir();
    $htaccess_file = trailingslashit( $uploads['basedir'] ) . '.htaccess';
    return insert_with_markers($htaccess_file, 'Themely Security', '');
}
register_deactivation_hook(__FILE__, 'themely_security_remove_uploads_htaccess');

/* 
 * Hide WP version strings from scripts and styles
 * https://wpengine.com/blog/15-ways-harden-wordpress-security/
*/
function themely_security_remove_wp_version_strings($src) {
	global $wp_version;
	parse_str(parse_url($src, PHP_URL_QUERY), $query);
	if ( !empty($query['ver']) && $query['ver'] === $wp_version ) {
		$src = remove_query_arg('ver', $src);
	}
	return $src;
}
add_filter( 'script_loader_src', 'themely_security_remove_wp_version_strings' );
add_filter( 'style_loader_src', 'themely_security_remove_wp_version_strings' );

/* 
 * Hide WP version strings from generator meta tag
*/
function themely_security_remove_version() {
	return '';
}
add_filter('the_generator', 'themely_security_remove_version');

/* 
 * Remove readme.html file
 * https://wpengine.com/blog/15-ways-harden-wordpress-security/
*/
function themely_security_remove_readme() {
    $readme_file = get_home_path() . 'readme.html';
    unlink($readme_file);
}
register_activation_hook(__FILE__, 'themely_security_remove_readme');


/* 
 * Add index.php file to uploads directory
*/
function themely_security_uploads_index() {
    $uploads = wp_get_upload_dir();
    $index_file = trailingslashit( $uploads['basedir'] ) . 'index.php';
    $content = "Access restricted!";
    fopen($index_file, 'w+');
    fwrite($index_file, $content);
    fclose($index_file);
}
register_activation_hook(__FILE__, 'themely_security_uploads_index');

/* 
 * Change WordPress salts & keys
*/

/* 
 * Disable file editing
 * Using "DISALLOW_FILE_EDIT" helps prevent an attacker from changing your files through WordPress backend.
*/

/* 
 * Change wp-admin url
 * https://wordpress.stackexchange.com/a/147881
*/

/* 
 * Enable automatic WordPress core updates
 * https://wordpress.org/support/article/configuring-automatic-background-updates/
*/
add_filter( 'auto_update_core', '__return_true' );

/* 
 * Enable automatic theme updates
*/
add_filter( 'auto_update_theme', '__return_true' );

/* 
 * Enable automatic plugin updates
*/
add_filter( 'auto_update_plugin', '__return_true' );

/* 
 * Remove website url field from comment forms
 * https://www.wpbeginner.com/plugins/how-to-remove-website-url-field-from-wordpress-comment-form/
*/
function themely_security_remove_url_field($fields) {
    if( isset($fields['url']) ) {
       unset($fields['url']);
       return $fields;
   }
}
add_filter('comment_form_default_fields', 'themely_security_remove_url_field');

/* 
 * Match captcha on login, registration and comment forms
 * https://wordpress.org/plugins/block-spam-by-math/advanced/
*/
class ThemelySecurityMathCaptcha {

    // Constructor
    function __construct() {
        add_action( 'register_form', array( $this, 'add_hidden_fields' ) );
        add_action( 'login_form', array( $this, 'add_hidden_fields' ) );
        add_action( 'comment_form_after_fields', array( $this, 'add_hidden_fields' ) );
        add_action( 'register_post', array( $this, 'register_post' ), 10, 2 );
        add_action( 'wp_authenticate', array( $this, 'wp_authenticate' ), 10, 2 );
        add_filter( 'preprocess_comment', array( $this, 'preprocess_comment' ) );
    }
    
    // Add hidden fields to the form
    function add_hidden_fields() {
        $mathvalue0 = rand(2, 15);
        $mathvalue1 = rand(2, 15);
        echo '<p>';
        echo "<label for='math_captcha'>Math CAPTCHA: $mathvalue0 + $mathvalue1 = ?</label>";            
        echo '<input type="text" id="mathvalue2" name="mathvalue2" class="input" size="20" />';
        echo '</p>';
        echo '<p style="display:none">';
        echo "<input type='text' name='mathvalue0' value='$mathvalue0' />";
        echo "<input type='text' name='mathvalue1' value='$mathvalue1' />";
        echo '</p>';
    }
    
    //  Protection function for submitted register form
    function register_post( $user_login, $user_email ) {
        if ( ( $user_login != '' ) && ( $user_email != '' ) ) {
            $this->check_hidden_fields();
        }
    }
    
    // Protection function for submitted login form
    function wp_authenticate( $user_login, $user_password ) {
        if ( ( $user_login != '' ) && ( $user_password != '' ) ) {
            $this->check_hidden_fields();
        }
    }
    
    // Protection function for submitted comment form
    function preprocess_comment( $commentdata ) {
        $this->check_hidden_fields();
        return $commentdata;
    }
    
    // Check for hidden fields and wp_die() in case of error
    function check_hidden_fields() {
        // Get values from POST data
        $val0 = '';
        $val1 = '';
        $val2 = '';
        if ( isset( $_POST['mathvalue0'] ) ) {
            $val0 = $_POST['mathvalue0'];
        }
        if ( isset( $_POST['mathvalue1'] ) ) {
            $val1 = $_POST['mathvalue1'];
        }
        if ( isset( $_POST['mathvalue2'] ) ) {
            $val2 = $_POST['mathvalue2'];
        }
        
        // Check values
        if ( ( $val0 == '' ) || ( $val1 == '' ) || ( intval($val2) != (intval($val0) + intval($val1)) ) ) {
            // Die and return error 403 Forbidden
            wp_die( 'Please enter the correct number for the Math CAPTCHA field', '403 Forbidden', array( 'response' => 403 ) );
        }
    }
}

// Ban heavy spammer's IPs
$ip = @ip2long( $_SERVER['REMOTE_ADDR'] );
if ( ( $ip !== -1 ) && ( $ip !== false )) {
    // Banned address spaces
    $banned_ranges = array(
        // Dragonara Alliance Ltd (194.8.74.0 - 194.8.75.255)
        array( '194.8.74.0', '194.8.75.255' ),
    );
    foreach( $banned_ranges as $range ) {
        $block = false;
        if ( is_array( $range ) ) {
            if ( ( $ip >= ip2long( $range[0] ) ) && ( $ip <= ip2long( $range[1] ) ) ) {
                $block = true;
            }
        } else {
            if ( $ip == ip2long( $range ) ) {
                $block = true;
            }
        }
        
        if ( $block ) {
            wp_die( 'ACCESS RESTRICTED!', '403 Forbidden', array( 'response' => 403 ) );
        }
    }
}
new ThemelySecurityMathCaptcha();