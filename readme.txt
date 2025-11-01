=== Xero WooCommerce Invoicing Connector ===
Contributors: wemakethings
Donate link: https://paypal.me/wemakethingsuk
Tags: woocommerce, xero, invoicing, accounting, orders, sync
Requires at least: 6.0
Tested up to: 6.6
WC requires at least: 6.0
WC tested up to: 8.8
Stable tag: 1.0.0
License: GPL-2.0+
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Automatically creates and registers paid invoices in Xero upon WooCommerce order completion.

== Description ==

The **Xero WooCommerce Invoicing Connector** seamlessly integrates your e-commerce platform with your Xero accounting software, eliminating manual data entry and ensuring your financials are always up-to-date.

This plugin automatically handles the creation of invoices in Xero as soon as a customer completes a payment and their WooCommerce order is marked as *completed*. It handles various payment methods, and accurately maps customer and product data to your Xero contacts and items.

**Key Features:**

* **Automated Invoice Creation:** Generates a corresponding invoice in Xero instantly when a WooCommerce order is paid and completed.
* **Accurate Data Mapping:** Correctly maps customer details, product line items, discounts, and shipping charges.
* **Tax Compliance:** Ensures all applicable sales tax/VAT rules are correctly transferred to the Xero invoice.
* **Payment Handling:** Registers the payment against the invoice in Xero, marking it as paid (based on your configuration).
* **Error Logging:** Includes robust logging to help diagnose and resolve any synchronization issues.

== Installation ==

### 1. Standard Installation

1.  Upload the entire `xero-woocommerce-invoicing-connector` folder to the `/wp-content/plugins/` directory.
2.  Activate the plugin through the 'Plugins' menu in WordPress.

### 2. Configuration

1.  Navigate to the woocommerce->Xero Invoicing settings page.
2.  Make a note of the redirect URI shown
3.  You will need a Xero App. 
3a.  Log into the Xero developers portal: https://developer.xero.com/
3b.  Click on New App and give it a suitable name (<mystore> sync)
3c.  Select mobile or desktop app, put in your store website, and the redirect uri from step 2. Read the terms and conditions, and click Create App
3d.  Go to the configuration page, and you can grab the client ID
4.  Add the client ID on the Xero Invoicing settings page and press save changes
5.  Click on Connect to Xero App, select the org you want to connect to, and click connect.
6.  You can now set the default sales account code, and the mapping for payment methods to bank accounts.

== Usage

At this point, its all configured and whenever an order moves to 'Completed', then it will be synced to Xero. If the product isn't in xero it will be created (matched on SKU), as will the customer. It will automatically be marked as paid, and assigned to the correct bank account, depending on your mappings.

== Frequently Asked Questions ==

= Does this plugin support refunds or cancelled orders? =
Version 1.0.0 focuses on the initial invoice creation for completed orders. Support for automated credit notes (for refunds) and cancelling pending invoices is planned for a future update.

= Where do I find the logs if a sync fails? =
The plugin logs all successful and failed synchronization attempts. You can find these under the **WooCommerce > Status > Logs** area, filtered by 'Xero Connector'.

= Can I choose which organisation in Xero to connect to? =
Yes, during the initial OAuth setup, you will be prompted to select the specific Xero organisation you wish to connect and sync data with.

== Changelog ==

= 1.0.0 =
* Initial public release.
* Core functionality for automatic invoice creation upon order completion.
* OAuth 2.0 support for secure Xero connection.
* Customer, product line item, and tax data mapping.

== Upgrade Notice ==

= 1.0.0 =
This is the first stable release. No upgrade notice is required.