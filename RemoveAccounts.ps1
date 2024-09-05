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
            # Getting session ID using query user or quser
            $sessionInfo = (query user | Select-String $username | ForEach-Object { $_.Line -split '\s+' })
            $sessionId = $sessionInfo[2]  # Assuming session ID is in the third column
            
            # Try logging off the user
            logoff $sessionId /server:localhost
            Start-Sleep -Seconds 5  # Short wait to allow logoff to complete

            # Check if session still exists and kill it if needed
            $sessionCheck = query user | Select-String $username
            if ($sessionCheck) {
                Write-Output "Session for $username still active. Attempting to forcefully kill session..."
                # Kill the session forcefully if logoff didn't work
                tskill $sessionId /server:localhost
                Write-Output "$username's session was forcefully killed."
            } else {
                Write-Output "$username logged off successfully."
            }

        } catch {
            Write-Output "Failed to log off or kill session for $username."
        }

        # Kill any lingering processes owned by the user
        try {
            Get-Process -IncludeUserName | Where-Object { $_.UserName -eq $username } | Stop-Process -Force
            Write-Output "Killed lingering processes for $username."
        } catch {
            Write-Output "Failed to stop some processes for $username."
        }
    }

    # Restart Remote Desktop Services (TermService) to clear any remaining sessions
    try {
        Restart-Service -Name TermService -Force
        Write-Output "Remote Desktop Services (TermService) restarted to clear lingering sessions."
    } catch {
        Write-Output "Failed to restart TermService."
    }

    # Restart User Profile Service to ensure profiles are unloaded
    try {
        Restart-Service -Name ProfSvc -Force
        Write-Output "User Profile Service (ProfSvc) restarted to ensure profile cleanup for $username."
    } catch {
        Write-Output "Failed to restart User Profile Service."
    }

    # Remove profile using WMI (Remove-UserProfile)
    try {
        Write-Output "Removing user profile for $username with SID $sid..."
        $userProfile = Get-WmiObject -Class Win32_UserProfile | Where-Object { $_.SID -eq $sid }
        if ($userProfile) {
            $userProfile.Delete()
            Write-Output "User profile removed for $username."
        } else {
            Write-Output "Profile for $username not found."
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
