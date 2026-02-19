# NP Order Hub

Central order list for multiple WooCommerce stores. Orders are sent to the hub via WooCommerce webhooks.

## Install
1. Copy `np-order-hub` to `wp-content/plugins/` on `ordre.nordicprofil.no`.
2. Activate **NP Order Hub** in WordPress.
3. Go to **Order Hub -> Stores** and add each store.

## Dashboard
The hub includes a simple admin dashboard at **Order Hub -> Dashboard** with totals, filters, and the latest orders.

## Store setup
For each store, create webhooks in **WooCommerce -> Settings -> Advanced -> Webhooks**:

- **Topic:** Order created
- **Delivery URL:** use the Webhook URL shown on the hub store row (it includes `?store=KEY`)
- **Secret:** use the same secret you saved in the hub store record
- **API Version:** v3
- **Status:** Active

Repeat with **Order updated** (recommended). Optional: **Order refunded** if you want refunds to update status in the hub.

## Order links
The hub shows **Open order** which links to the store admin order page.

- **Legacy:** `post.php?post=ID&action=edit`
- **HPOS:** `admin.php?page=wc-orders&action=edit&id=ID`

Choose the right type when adding the store.

## Packing slip link
If you want the hub to open the store's packing slip layout, add a **Packing Slip URL** when you create the store:

- Copy the packing slip URL from the store admin and replace the order ID with `{order_id}`.
- Example (WPO PDF Invoices & Packing Slips):
  `https://store.com/wp-admin/admin-ajax.php?action=generate_wpo_wcpdf&document_type=packing-slip&order_ids={order_id}`

The hub will show a **Packing slip** button on the dashboard and order details.

If your packing slip link requires an access key, use `{access_key}` and install the helper snippet on each store (see below).

## WPO access key helper (stores)
For WPO "Full" access, add this helper plugin on each store so the webhook includes an access key:

1. Copy `np-order-hub-store-wpo.php` to the store's `wp-content/plugins/`.
2. Activate **NP Order Hub - WPO Access Key**.
3. Update your hub Packing Slip URL to include `{access_key}`:
   `https://store.com/wp-admin/admin-ajax.php?action=generate_wpo_wcpdf&document_type=packing-slip&order_ids={order_id}&access_key={access_key}`

## Notes
- Use a unique secret per store.
- The hub stores order snapshots in a custom table for speed.
- If a store changes domain, update the store URL in the hub.
