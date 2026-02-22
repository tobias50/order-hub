#!/usr/bin/env php
<?php

declare(strict_types=1);

$root = realpath(__DIR__ . '/..');
if (!is_string($root) || $root === '') {
    fwrite(STDERR, "Could not resolve project root.\n");
    exit(2);
}
chdir($root);

$chunkTarget = getenv('CHUNK_SIZE');
$chunk = is_string($chunkTarget) && ctype_digit($chunkTarget) ? max(80, (int) $chunkTarget) : 250;

$modules = [
    [
        'source' => 'mu-plugins/np-order-hub/np-order-hub.php',
        'runtime' => 'mu-plugins/np-order-hub/np-order-hub-refactor/includes/modules/001-runtime-main.php',
    ],
    [
        'source' => 'mu-plugins/np-order-hub/np-order-hub-store-wpo.php',
        'runtime' => 'mu-plugins/np-order-hub/np-order-hub-store-wpo-refactor/includes/modules/001-runtime-main.php',
    ],
];

$loadSource = static function (string $sourceRel): string {
    $fromGit = shell_exec('git show HEAD:' . escapeshellarg($sourceRel) . ' 2>/dev/null');
    if (is_string($fromGit) && $fromGit !== '') {
        return $fromGit;
    }

    $path = $sourceRel;
    if (!is_file($path)) {
        return '';
    }

    $content = (string) file_get_contents($path);
    return $content;
};

$patchSource = static function (string $sourceRel, string $content): string {
    if ($sourceRel === 'mu-plugins/np-order-hub/np-order-hub.php') {
        $replacements = [
            "register_activation_hook(__FILE__, 'np_order_hub_activate');" =>
                "\$np_order_hub_main_file = defined('NP_ORDER_HUB_MAIN_FILE') ? NP_ORDER_HUB_MAIN_FILE : __FILE__;\nregister_activation_hook(\$np_order_hub_main_file, 'np_order_hub_activate');",
            "\$base = __DIR__ . '/vendor/setasign';" =>
                "    \$np_order_hub_main_file = defined('NP_ORDER_HUB_MAIN_FILE') ? NP_ORDER_HUB_MAIN_FILE : __FILE__;\n    \$base = dirname(\$np_order_hub_main_file) . '/vendor/setasign';",
            "    \$path = plugin_dir_path(__FILE__) . 'assets/pushover-logo.svg';" =>
                "    \$np_order_hub_main_file = defined('NP_ORDER_HUB_MAIN_FILE') ? NP_ORDER_HUB_MAIN_FILE : __FILE__;\n    \$path = plugin_dir_path(\$np_order_hub_main_file) . 'assets/pushover-logo.svg';",
            "    return plugins_url('assets/pushover-logo.svg', __FILE__);" =>
                "    return plugins_url('assets/pushover-logo.svg', \$np_order_hub_main_file);",
            "        \$plugin_url = plugins_url('/', __FILE__);" =>
                "        \$np_order_hub_main_file = defined('NP_ORDER_HUB_MAIN_FILE') ? NP_ORDER_HUB_MAIN_FILE : __FILE__;\n        \$plugin_url = plugins_url('/', \$np_order_hub_main_file);",
            "            \$file_path = plugin_dir_path(__FILE__) . str_replace('/', DIRECTORY_SEPARATOR, \$relative);" =>
                "            \$file_path = plugin_dir_path(\$np_order_hub_main_file) . str_replace('/', DIRECTORY_SEPARATOR, \$relative);",
        ];

        return str_replace(array_keys($replacements), array_values($replacements), $content);
    }

    if ($sourceRel === 'mu-plugins/np-order-hub/np-order-hub-store-wpo.php') {
        return str_replace(
            "register_activation_hook(__FILE__, 'np_order_hub_wpo_activate');",
            "\$np_order_hub_wpo_main_file = defined('NP_ORDER_HUB_WPO_MAIN_FILE') ? NP_ORDER_HUB_WPO_MAIN_FILE : __FILE__;\nregister_activation_hook(\$np_order_hub_wpo_main_file, 'np_order_hub_wpo_activate');",
            $content
        );
    }

    return $content;
};

$writeLoader = static function (string $runtimePath): void {
    $loader = <<<'PHP'
<?php
if (!defined('ABSPATH')) {
    exit;
}

$np_runtime_segments = glob(__DIR__ . '/001-runtime-main.d/001-runtime-main-seg-*.php');
if (is_array($np_runtime_segments)) {
    sort($np_runtime_segments, SORT_NATURAL);
    foreach ($np_runtime_segments as $np_runtime_segment) {
        if (is_readable($np_runtime_segment)) {
            require_once $np_runtime_segment;
        }
    }
}
PHP;

    file_put_contents($runtimePath, $loader . "\n");
};

$segmentContent = static function (string $content, int $chunkLines): array {
    $tokens = token_get_all($content);

    $segments = [];
    $buffer = '';
    $lineCount = 0;
    $curly = 0;
    $paren = 0;
    $square = 0;
    $firstOpenTagSkipped = false;

    $flush = static function () use (&$segments, &$buffer, &$lineCount): void {
        $trimmed = trim($buffer);
        if ($trimmed === '') {
            $buffer = '';
            $lineCount = 0;
            return;
        }
        $segments[] = $buffer;
        $buffer = '';
        $lineCount = 0;
    };

    foreach ($tokens as $tok) {
        $text = is_array($tok) ? $tok[1] : $tok;
        $id = is_array($tok) ? $tok[0] : null;

        if (($id === T_OPEN_TAG || $id === T_OPEN_TAG_WITH_ECHO) && !$firstOpenTagSkipped) {
            $firstOpenTagSkipped = true;
            continue;
        }

        $buffer .= $text;
        $lineCount += substr_count($text, "\n");

        $safeBoundary = false;
        if (!is_array($tok)) {
            if ($tok === '{') {
                $curly++;
            } elseif ($tok === '}') {
                $curly = max(0, $curly - 1);
            } elseif ($tok === '(') {
                $paren++;
            } elseif ($tok === ')') {
                $paren = max(0, $paren - 1);
            } elseif ($tok === '[') {
                $square++;
            } elseif ($tok === ']') {
                $square = max(0, $square - 1);
            }

            if ($curly === 0 && $paren === 0 && $square === 0 && ($tok === ';' || $tok === '}')) {
                $safeBoundary = true;
            }
        }

        if ($safeBoundary && $lineCount >= $chunkLines) {
            $flush();
        }
    }

    if (trim($buffer) !== '') {
        $flush();
    }

    return $segments;
};

$segmentedCount = 0;

foreach ($modules as $module) {
    $sourceRel = (string) $module['source'];
    $runtimeRel = (string) $module['runtime'];

    $source = $loadSource($sourceRel);
    if ($source === '') {
        fwrite(STDERR, "Failed to read source content for {$sourceRel}\n");
        exit(3);
    }

    $source = $patchSource($sourceRel, $source);

    $segments = $segmentContent($source, $chunk);
    if (empty($segments)) {
        fwrite(STDERR, "No segments generated for {$sourceRel}\n");
        exit(4);
    }

    $runtimePath = $root . '/' . $runtimeRel;
    $segDir = dirname($runtimePath) . '/001-runtime-main.d';
    if (!is_dir($segDir) && !mkdir($segDir, 0777, true) && !is_dir($segDir)) {
        fwrite(STDERR, "Could not create segment dir {$segDir}\n");
        exit(5);
    }

    $existing = glob($segDir . '/001-runtime-main-seg-*.php');
    if (is_array($existing)) {
        foreach ($existing as $old) {
            @unlink($old);
        }
    }

    $index = 1;
    foreach ($segments as $segment) {
        $filename = sprintf('%s/001-runtime-main-seg-%03d.php', $segDir, $index);
        $segmentBody = ltrim($segment, "\n");
        file_put_contents($filename, "<?php\n" . $segmentBody);
        $index++;
    }

    $writeLoader($runtimePath);
    fwrite(STDOUT, sprintf("Segmented %s into %d files\n", $sourceRel, count($segments)));
    $segmentedCount++;
}

fwrite(STDOUT, sprintf("Done. Segmented modules: %d\n", $segmentedCount));
exit(0);
