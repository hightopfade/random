Function convertHex($ip){
	$chararray = [char[]]$ip
	$val = 0
	while ($val -ne $chararray.Length) {
		$converted =  $converted + "0x"
		$converted += [System.String]::Format("{0:X}",[System.Convert]::ToUInt32($chararray[$val]))
		$converted += ","
		$val++
	}
	return $converted
}

[string]$ip = "192.168.1.245"
convertHex($ip)

# Convert to decimal byte array
#[System.Text.Encoding]::UTF8.GetBytes('192.168.1.245') -join ",0x"