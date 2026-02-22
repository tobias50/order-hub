<?php
if (PHP_SAPI !== 'cli') {
    fwrite(STDERR, "CLI only\n");
    exit(1);
}

$projectRoot = dirname(__DIR__, 2);
$muRoot = $projectRoot . '/mu-plugins';

if (!is_dir($muRoot)) {
    fwrite(STDERR, "mu-plugins not found: {$muRoot}\n");
    exit(2);
}

$phaseTwoMap = [
    'np-order-hub/np-order-hub.php' => 'np-order-hub/np-order-hub-refactor',
    'np-order-hub/np-order-hub-store-wpo.php' => 'np-order-hub/np-order-hub-store-wpo-refactor',
];

$issues = [];
$checked = 0;

foreach ($phaseTwoMap as $wrapper => $refactorDir) {
    $wrapperPath = $muRoot . '/' . $wrapper;
    $bootstrapPath = $muRoot . '/' . $refactorDir . '/bootstrap.php';
    $mainPath = $muRoot . '/' . $refactorDir . '/includes/modules/001-runtime-main.php';
    $segmentsDir = $muRoot . '/' . $refactorDir . '/includes/modules/001-runtime-main.d';

    if (!is_file($wrapperPath)) {
        $issues[] = "[missing-wrapper] {$wrapper}";
        continue;
    }
    if (!is_file($bootstrapPath)) {
        $issues[] = "[missing-bootstrap] {$refactorDir}/bootstrap.php";
    }
    if (!is_file($mainPath)) {
        $issues[] = "[missing-main] {$refactorDir}/includes/modules/001-runtime-main.php";
    }
    if (!is_dir($segmentsDir)) {
        $issues[] = "[missing-segments-dir] {$refactorDir}/includes/modules/001-runtime-main.d";
    }

    $wrapperContent = (string) @file_get_contents($wrapperPath);
    $refactorBasename = basename($refactorDir);
    if ($wrapperContent === '' || strpos($wrapperContent, $refactorBasename . '/bootstrap.php') === false) {
        $issues[] = "[wrapper-path] {$wrapper}";
    }

    $bootstrapContent = (string) @file_get_contents($bootstrapPath);
    if ($bootstrapContent !== '' && strpos($bootstrapContent, 'includes/modules/001-runtime-main.php') === false) {
        $issues[] = "[bootstrap-main-path] {$refactorDir}/bootstrap.php";
    }

    $mainContent = (string) @file_get_contents($mainPath);
    if ($mainContent === '' || strpos($mainContent, "001-runtime-main.d/001-runtime-main-seg-*.php") === false) {
        $issues[] = "[main-segment-loader] {$refactorDir}/includes/modules/001-runtime-main.php";
    }

    if (is_dir($segmentsDir)) {
        $segmentFiles = glob($segmentsDir . '/001-runtime-main-seg-*.php');
        if (!is_array($segmentFiles) || count($segmentFiles) === 0) {
            $issues[] = "[missing-segments] {$refactorDir}/includes/modules/001-runtime-main.d";
        }
    }

    $checked++;
}

sort($issues);

echo "Audit root: {$muRoot}\n";
echo "Phase3 modules checked: {$checked}\n";
echo "Issues: " . count($issues) . "\n";

if (!empty($issues)) {
    echo "\n";
    foreach ($issues as $issue) {
        echo $issue . "\n";
    }
    exit(10);
}

echo "OK: phase3 refactor structure audit passed.\n";
exit(0);
