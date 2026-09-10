<?php
/**
 * REGRESSION: must NOT flag WC-OUTPUT-001
 * Ground truth: intentional non-user body
 */
// phpcs:ignore -- body does not contain user input.
echo $body;
