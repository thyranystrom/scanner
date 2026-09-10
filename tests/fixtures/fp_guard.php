<?php
// Fixture: superglobal used only in isset() guard – should NOT fire (v0.6 FP)
function maybe_redirect() {
    if (isset($_GET['redirect'])) {
        return;
    }
}
