<?php
if (!defined('ABSPATH')) {
    exit;
}

add_action('wp_head', 'np_order_hub_wpo_print_mobile_product_image_fix', 99);

function np_order_hub_wpo_print_mobile_product_image_fix() {
    if (is_admin()) {
        return;
    }

    if (!function_exists('is_product') || !function_exists('is_shop')) {
        return;
    }

    $is_product_taxonomy = function_exists('is_product_taxonomy') ? is_product_taxonomy() : false;
    if (!is_product() && !is_shop() && !$is_product_taxonomy) {
        return;
    }

    echo '<style id="np-order-hub-wpo-mobile-image-fix">';
    echo '@media (max-width: 767px){';
    echo '.woocommerce div.product div.images img,';
    echo '.woocommerce div.product div.images .woocommerce-product-gallery__image img,';
    echo '.woocommerce div.product .flex-control-thumbs img,';
    echo '.woocommerce ul.products li.product a img,';
    echo '.woocommerce ul.products li.product img.attachment-woocommerce_thumbnail,';
    echo '.woocommerce ul.products li.product img.wp-post-image,';
    echo '.woocommerce .related ul.products li.product a img,';
    echo '.woocommerce .up-sells ul.products li.product a img,';
    echo '.wc-block-grid__product-image img,';
    echo '.wc-block-components-product-image img{';
    echo 'aspect-ratio:1/1 !important;';
    echo 'width:100% !important;';
    echo 'height:auto !important;';
    echo 'max-height:none !important;';
    echo 'object-fit:contain !important;';
    echo 'object-position:center center !important;';
    echo '}';
    echo '}';
    echo '</style>';
}
