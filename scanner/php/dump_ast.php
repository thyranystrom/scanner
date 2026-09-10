<?php
require_once __DIR__ . '/vendor/autoload.php';

use PhpParser\ParserFactory;

/**
 * Two modes:
 *   1. Single-file (legacy):  php dump_ast.php <file_path>
 *      Prints the bare AST array as JSON, or exits non-zero on error.
 *   2. Batch (stdin):         php dump_ast.php --batch < paths.txt
 *      Reads one file path per line from STDIN, parses every one in this
 *      SAME PHP process, and prints a single JSON object mapping each
 *      path to its AST (or null on a per-file parse failure -- one bad
 *      file must not abort the whole batch).
 *
 * Batch mode exists purely for performance: spawning a fresh PHP process
 * per file dominates scan time on any plugin with more than a handful of
 * files (measured: ~5.7s of PHP subprocess overhead out of a ~13s cold
 * scan against a 202-file real plugin). Parsing many files inside one
 * process call amortizes PHP's own startup cost (autoloading, opcache
 * warmup, etc.) across all of them instead of paying it 202 times.
 */

function build_parser()
{
    if (class_exists('PhpParser\ParserFactory')) {
        $factory = new ParserFactory();
        if (method_exists($factory, 'createForHostVersion')) {
            return $factory->createForHostVersion();
        } elseif (defined('PhpParser\ParserFactory::PREFER_PHP7')) {
            return $factory->create(ParserFactory::PREFER_PHP7);
        }
        return $factory->createForNewestSupportedVersion();
    }
    fwrite(STDERR, "PhpParser\\ParserFactory not found\n");
    exit(1);
}

function parse_one($parser, string $filePath)
{
    if (!file_exists($filePath)) {
        return null;
    }
    $code = file_get_contents($filePath);
    try {
        return $parser->parse($code);
    } catch (Throwable $e) {
        return null;
    }
}

if ($argc >= 2 && $argv[1] === '--batch') {
    $parser = build_parser();
    $results = [];
    while (($line = fgets(STDIN)) !== false) {
        $path = rtrim($line, "\r\n");
        if ($path === '') {
            continue;
        }
        $results[$path] = parse_one($parser, $path);
    }
    echo json_encode($results, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    exit(0);
}

if ($argc < 2) {
    fwrite(STDERR, "Usage: php dump_ast.php <file_path>\n");
    fwrite(STDERR, "       php dump_ast.php --batch < paths.txt\n");
    exit(1);
}

$filePath = $argv[1];
if (!file_exists($filePath)) {
    fwrite(STDERR, "File not found: {$filePath}\n");
    exit(1);
}

$parser = build_parser();
$ast = parse_one($parser, $filePath);
if ($ast === null) {
    fwrite(STDERR, "Parse error or file not found: {$filePath}\n");
    exit(1);
}
echo json_encode($ast, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
