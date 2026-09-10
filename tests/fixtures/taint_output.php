<?php
// Fixture: tainted variable reaches echo (should be MEDIUM)
function render_name() {
    $name = $_POST['name'];
    echo $name;
}
