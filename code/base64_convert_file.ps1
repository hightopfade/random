param([string]$file)
$ff = get-childitem $file
$out = $ff.directoryname + '\' + $ff.basename + '.png'
$b64 = get-content $ff
$bytes = [convert]::fromBase64string($b64)
[IO.File]::WriteAllBytes($out, $bytes)