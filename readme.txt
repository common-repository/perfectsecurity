=== Plugin Name ===
Contributors: IAmFoxx
Donate link: N/A
Tags: security, spam
Requires at least: 4.6
Tested up to: 4.9.6
Stable tag: 1.7.8
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

PerfectSecurity protects your WordPress login from malicious users and IP addresses.

== Description ==

PerfectSecurity uses the PerfectSyntax Security API to check IP addresses of anyone who attempts to access your WordPress login.
If the IP address is known to be malicious, they are blocked from accessing, no need for you to worry!

Other features include:
* IP Blacklist
* Country Whitelist (Only allow specific countries to access your login page)
* High request blocking (too many requests = temporary ban)
* Disable the XML-RPC interface.
* More to come!

== Installation ==

1. Upload the plugin files to the `/wp-content/plugins/perfectsecurity` directory, or install the plugin through the WordPress plugins screen directly.
1. Activate the plugin through the 'Plugins' screen in WordPress
1. Use the Settings->PerfectSecurity screen to configure the plugin
1. Enter your API Key and UserID into the boxes and save.
1. Done.


== Frequently Asked Questions ==

= How do I get an API Key? =

API Keys are available by creating an account at https://perfectsecurity.network and visiting the API Key section.

= How accurate is the IP lookup? =

While we can never be 100% certain on if an IP is malicious, we track numerous variables and use custom algorithms to get our results.
If at any point an IP is blocked that shouldn't an email can be sent to appeals@perfectsyntax.uk with further details.

= Can I view the stats? =

Of course! The core goal of the system is to educate and avise, we provide an in-depth dashboard at https://perfectsecurity.network.
Using the dashboard will allow you to see details on country of origin, number of black/whitelisted IP addresses and more!


== Changelog ==

= 1.7.8 =
* Fixed a bug which would cause the headers not to be processed.

= 1.7.7 =
* Additonal header checks for accuracy.

= 1.7.5 =
* Updates to retrieve user agent header.

= 1.6.5 =
* Initial plugin public release.

== Screenshots ==

== Upgrade Notice ==

== Arbitrary section ==
