<?php
/*
    Plugin Name: PerfectSecurity
    Plugin URI: https://perfectsecurity.network
    Description: PerfectSyntax WordPress Security, provides an extra layer of security for your site.
    Author: PerfectSyntax
    Version: 1.7.8
    Author URI: https://perfectsyntax.uk
    License: GPLv2 or later
    License URI: https://www.gnu.org/licenses/gpl-2.0.html
*/

/******************************        Includes  ****************************/
$plugin_dir = plugin_dir_path( __FILE__ );

// JWT Helper.
require_once($plugin_dir . '/jwt_helper.php');

/****************************** Admin Area, f->h ****************************/

//              FUNCTIONS

// Add PSSec to the admin menu. #1
function pssec_admin_menu() {
    add_options_page("PerfectSecurity", "PerfectSecurity", "manage_options", "pssec", 'pssec_admin_display');
}

// Display the contents of the PSSec admin page.
function pssec_admin_display()
{ ?>
    <div>
        <h1>PerfectSecurity</h1>
        <form method="post" action="options.php">
            <?php settings_fields( 'pssec_api_grp' ); ?>
            <?php do_settings_sections( 'pssec_api_grp' ); ?>
            <?php
                $ignore_wl = get_option('pssec_ignore_whitelist');
                $ignore_bl = get_option('pssec_ignore_blacklist');
                $ignore_req = get_option('pssec_ignore_high_requests');
                $country_white = get_option('pssec_country_whitelist');
            ?>
            <table class="form-table">
                <tr valign="top">
                    <th scope="row">API Key</th>
                    <td><input type="text" name="pssec_api_key" value="<?php echo esc_attr( get_option('pssec_api_key') ); ?>" required /></td>
                    <td>Your API Key is unique to you and can be used on as many WordPress sites as you require, please ensure the correct hostname is provided.</td>
                </tr>

                <tr valign="top">
                    <th scope="row">User ID</th>
                    <td><input type="text" name="pssec_user_id" value="<?php echo esc_attr( get_option('pssec_user_id') ); ?>" required/></td>
                    <td>This is your unique UserID </td>
                </tr>

                <tr valign="top">
                    <th scope="row">Hostname</th>
                    <td><input type="text" name="pssec_host" value="<?php echo esc_attr( get_option('pssec_host', str_replace("www.", "", $_SERVER['SERVER_NAME']))); ?>" required/></td>
                    <td>This is the URL of the current site, unless something is very wrong, you shouldn't need to change this.</td>
                </tr>

                <tr valign="top">
                    <th scope="row">Ignore Whitelist</th>
                    <td><input type="checkbox" name="pssec_ignore_whitelist" <?php if($ignore_wl == true) echo "checked"; ?>/></td>
                    <td>Enabling this option will disable the whitelist, causing whitelisted IP addresses to be subject to security checks.</td>
                </tr>

                <tr valign="top">
                    <th scope="row">Ignore Blacklist</th>
                    <td><input type="checkbox" name="pssec_ignore_blacklist" <?php if($ignore_bl == true) echo "checked"; ?>/></td>
                    <td>Enabling this option will allow blacklisted IP addresses to access the site, provided they pass the remaining checks.</td>
                </tr>

                <tr valign="top">
                    <th scope="row">Ignore High Requests</th>
                    <td><input type="checkbox" name="pssec_ignore_high_requests" <?php if($ignore_req == true) echo "checked"; ?>/></td>
                    <td>Enabling this option will allow IP addresses which have made more than the High Request Threshold within the previous 15 minutes to access the site.</td>
                </tr>

                <tr valign="top">
                    <th scope="row">High Request Threshold</th>
                    <td><input type="text" name="pssec_high_request_count" value="<?php echo esc_attr( get_option('pssec_high_request_count', 15) ); ?>" /></td>
                    <td>Any IP address which has made more than this number of requests within the past 15 minutes will be temporarily stopped from accessing the site.</td>
                </tr>

                <tr valign="top">
                    <th scope="row">Use Country Whitelist</th>
                    <td><input type="checkbox" name="pssec_country_whitelist" <?php if($country_white == true) echo "checked"; ?>/></td>
                    <td>Allow access only from countries specified in the whitelist below.</td>
                </tr>

                <tr valign="top">
                    <th scope="row">Whitelisted Countries</th>
                    <td><input type="text" name="pssec_countries_whitelisted" value="<?php echo esc_attr( get_option('pssec_countries_whitelisted') ); ?>" /></td>
                    <td>Only allow access from countries named in this list.</td>
                </tr>

            </table>

            <?php submit_button(); ?>

        </form>
    </div>
<?php
}


//              HOOKS

add_action('admin_menu', 'pssec_admin_menu');


/****************************** Plugin Mechanic, f->h ****************************/

//              FUNCTIONS

// Query the API of the IP address accessing the login form.
function pssec_login_ip_check() {
    // Get X-Forwarded-For (CloudFlare) or standard IP.
    if ($_SERVER['HTTP_X_FORWARDED_FOR']){
        $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
    }
    else{
        $ip = $_SERVER['REMOTE_ADDR'];
    }

    // Get the UA of the request.
    $ua = $_SERVER['HTTP_USER_AGENT'];

    // The details here.
    $this_host = get_option("pssec_host", $_SERVER['SERVER_NAME']);
    $this_user = get_option("pssec_user_id");
    $this_key = get_option("pssec_api_key");

    //Use FIRST IP if available.
    $exp = explode(",", $ip);
    $ip = esc_url($exp[0]);
    $ip = preg_replace('#^https?://#', '', $ip); //Remove HTTP/s from IP.

    // Create the JWT payload for the API Key.
    $payload = array(
        'userid' => $this_user,
        'host' => $this_host);

    // Create JWT and key.
    $jwt = new JWT();
    $api_key = $jwt->encode($payload, $this_key);

    // Create header args for remote_get.
    $args = array(
        'user-agent' => 'PerfectSecurity - 1.6.5',
        'headers' => array(
            'X-API-KEY' => $api_key,
		'requesting-user-agent' => $ua
        ),
    );

    // API URL.
    $host = "https://api.perfectsecurity.network/ip/".$ip;
    
    // Use WordPress HTTP API to get data. (
    $result = wp_remote_get($host, $args);
    $result = wp_remote_retrieve_body($result);

    // Convert JSON to OBJ
    $api = json_decode($result);

    // Make sure there are no errors returned.
    if(!array_key_exists("error", $api))
    {
        // Pull some data from the database.
        $ignore_whitelist = get_option('pssec_ignore_whitelist', false);
        $ignore_blacklist = get_option('ssec_ignore_blacklist', false);
        $ignore_high_requests = get_option('pssec_ignore_high_requests', false);
        $high_request_count = get_option('pssec_high_request_count', 15);
        $use_country_whitelist = get_option('pssec_country_whitelist', false);
        $whitelised_countries = explode(',', get_option('pssec_countries_whitelisted', 'GB'));

        // Check if the IP is whitelisted and plugin is set to follow whitelist.
        if($api->ip->whitelisted == "true" && !$ignore_whitelist)
        {
            // Nothing to do. Everything is fine and dandy.
        }
        // IP is not whitelisted, and/or plugin is configured to ignore whitelist.
        else
        {
            // If the IP is blacklisted and plugin is set to follow blacklist.
            if($api->ip->blacklisted == "true" && !$ignore_blacklist)
            {
                // Create the error message.
                $message = "<p>Your IP address has been flagged for malicious activity and has been blocked.</p>";
                $message .= "<p>If you believe this to be in error, please email appeals at perfectsyntax.uk";
                // You shall not pass. (Kill all WP execution.)
                wp_die($message, "PerfectSecurity - Blocked", 432);
            //
            }

            // If the country whitelist is enabled and the country doesn't exist in the list. Block.
            if($use_country_whitelist && !in_array($api->ip->country, $whitelised_countries))
            {
                // Create the error message.
                $message = "<p>Your IP address originates from a country which has been blacklisted by this site.</p>";
                $message .= "<p>If you believe this to be in error, please email appeals at perfectsyntax.uk";
                // You shall not pass. (Kill all WP execution.)
                wp_die($message, "PerfectSecurity - Blocked", 434);
            }

            // If the IP has made more than the defined high request count in 15 minutes, and plugin set to block.
            if($api->ip->recent_requests > intval($high_request_count) && !$ignore_high_requests)
            {
                // Create the error message.
                $message = "<p>Your IP address has made too many login attempts and has been temporarily restricted from accessing.</p>";
                $message .= "<p>If you believe this to be in error, please email appeals at perfectsyntax.uk";
                // You shall not pass. (Kill all WP execution.)
                wp_die($message, "PerfectSecurity - Too Many Requests", 433);
            }

        }

    }

}

function pssec_login_status() {
    // Pull settings.
    $this_host = get_option("pssec_host", $_SERVER['SERVER_NAME']);
    $this_user = get_option("pssec_user_id");
    $this_key = get_option("pssec_api_key");

    // If all settings needed are set and not empty, display the authorised message.
    if(isset($this_host) && isset($this_user) && isset($this_key) && !empty($this_host) && !empty($this_user) && !empty($this_key)) {
        ?>
        <p>
            <small>Your IP Address <b>
                    <?php if ($_SERVER['HTTP_X_FORWARDED_FOR']) {
                        $visit = $_SERVER['HTTP_X_FORWARDED_FOR'];
                    } else {
                        $visit = $_SERVER['REMOTE_ADDR'];
                    }
                    $visit = explode(",", $visit);
                    esc_url($visit);
                    echo $visit[0];
                    ?>
                </b> has been authoirsed to access this site.
            </small>
            <br/><br/></p>
        <?php
    }
}



//              HOOKS
add_action('login_init', 'pssec_login_ip_check');
add_action('login_form', 'pssec_login_status');

//Disable XMLRPC. 
add_filter( 'xmlrpc_enabled', '__return_false' );


/****************************** Configs, f->h ****************************/

//              FUNCTIONS
function pssec_activate()
{
    // Add options.
    register_setting('pssec_api_grp', 'pssec_api_key');
    register_setting('pssec_api_grp', 'pssec_user_id');
    register_setting('pssec_api_grp', 'pssec_host');
    register_setting('pssec_api_grp', 'pssec_high_request_count');
    register_setting('pssec_api_grp', 'pssec_ignore_blacklist');
    register_setting('pssec_api_grp', 'pssec_ignore_whitelist');
    register_setting('pssec_api_grp', 'pssec_ignore_high_requests');
    register_setting('pssec_api_grp', 'pssec_country_whitelist');
    register_setting('pssec_api_grp', 'pssec_countries_whitelisted');

}


//              HOOKS
// Plugin activated.
add_action( 'admin_init','pssec_activate' );
