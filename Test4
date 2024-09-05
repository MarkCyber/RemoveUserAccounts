$usernames = @("John.doesNotexistttt", "Test.Account", "testingthis")
$loggedOnUsers = Get-WmiObject -Class Win32_ComputerSystem | Select-Object -ExpandProperty UserName

foreach ($username in $usernames) {
    # Find SID
    try {
        $sid = (New-Object System.Security.Principal.NTAccount($username)).Translate([System.Security.Principal.SecurityIdentifier]).Value
    } catch {
        Write-Output "Failed to find SID for $username. Skipping..."
        continue
    }

    # Log off if logged in
    if ($loggedOnUsers -contains $username) {
        try {
            # Getting session ID using quser
            $sessionId = (quser | Select-String $username | ForEach-Object { $_.Line -split '\s+' })[2]
            logoff $sessionId /server:localhost
            Start-Sleep -Seconds 5  # Optional: Wait for logoff to complete
            Write-Output "$username logged off successfully."
        } catch {
            Write-Output "Failed to log off $username."
        }
    }

    # Remove profile
    try {
        Write-Output "Removing user profile for $username with SID $sid..."
        $profilePath = Get-WmiObject -Class Win32_UserProfile | Where-Object { $_.SID -eq $sid } | Select-Object -ExpandProperty LocalPath
        if ($profilePath) {
            Remove-Item -Recurse -Force $profilePath
            Write-Output "User profile removed: $profilePath"
        } else {
            Write-Output "Profile path not found for $username."
        }
    } catch {
        Write-Output "Failed to remove profile for $username."
    }

    # Remove user's registry key from HKLM (ProfileList)
    $profileRegKeyPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$sid"
    try {
        Remove-Item -Path $profileRegKeyPath -Recurse -Force -ErrorAction SilentlyContinue
        Write-Output "Registry entry for $username ($sid) removed from ProfileList."
    } catch {
        Write-Output "Failed to remove registry entry for $username ($sid)."
    }

    # Clear the last logged on user in HKLM if it's in the list
    $lastLoggedOnUserRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI"
    try {
        $lastLoggedOnUser = (Get-ItemProperty -Path $lastLoggedOnUserRegPath -Name LastLoggedOnUser -ErrorAction SilentlyContinue).LastLoggedOnUser
        if ($lastLoggedOnUser -and ($usernames -contains $lastLoggedOnUser)) {
            Set-ItemProperty -Path $lastLoggedOnUserRegPath -Name LastLoggedOnUser -Value ""
            Write-Output "Cleared LastLoggedOnUser in registry because it matched $lastLoggedOnUser."
        }
    } catch {
        Write-Output "Failed to clear LastLoggedOnUser in the registry."
    }

    # Remove user's registry from HKCU (via HKEY_USERS)
    $hkuRegKeyPath = "HKEY_USERS\$sid"
    try {
        Remove-Item -Path $hkuRegKeyPath -Recurse -Force -ErrorAction SilentlyContinue
        Write-Output "Registry entry for $username ($sid) removed from HKEY_USERS."
    } catch {
        Write-Output "Failed to remove registry entry for $username ($sid) from HKEY_USERS."
    }
}
