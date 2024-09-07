###################################################################################################################################
###################################################################################################################################
##########                                                                                                               ##########
##########                     This script was created by MarkCyber at https://github.com/Markcyber                      ##########
##########        Replacement of the hardcoded usernames to the username you want deleted is the only requirement        ##########
##########       If you only want to remove user from login screen, then you can run it without changing usernames       ##########
##########           This account removal process is done via windows registry modification and profile deletion         ##########
##########                                                                                                               ##########
###################################################################################################################################
###################################################################################################################################
$usernames = @("John.doesNotexistttt", "Test.Account", "testingthis") #ADD THE USERNAME/S YOU WANT TO REMOVE HERE
$loggedOnUsers = Get-WmiObject -Class Win32_ComputerSystem | Select-Object -ExpandProperty UserName

foreach ($username in $usernames) {
    #Find SID
    try {
        $sid = (New-Object System.Security.Principal.NTAccount($username)).Translate([System.Security.Principal.SecurityIdentifier]).Value
    } catch {
        Write-Output "Failed to find SID for $username. Skipping..."
        continue
    }
    #Get session ID for the user
    try {
        $sessionInfo = (query user | Select-String $username | ForEach-Object { $_.Line -split '\s+' })
        $sessionId = $sessionInfo[2]  #Assuming session ID is in the third column
        $sessionState = $sessionInfo[3] #Assuming session state is in the fourth column
        #If session state is 'Disc', we need to log them off
        if ($sessionState -eq 'Disc') {
            Write-Output "User $username is disconnected. Logging off session ID $sessionId..."
            logoff $sessionId /server:localhost
            Start-Sleep -Seconds 5  #Short wait to allow logoff to complete
            #Check if session still exists and kill it if needed
            $sessionCheck = query user | Select-String $username
            if ($sessionCheck) {
                Write-Output "Session for $username still active. Attempting to forcefully kill session..."
                tskill $sessionId /server:localhost
                Write-Output "$username's session was forcefully killed."
            } else {
                Write-Output "$username logged off successfully."
            }
        } else {
            Write-Output "User $username does not have a disconnected session."
        }

    } catch {
        Write-Output "Failed to log off or kill session for $username."
    }
    #Kill any lingering processes owned by the user
    try {
        Get-Process -IncludeUserName | Where-Object { $_.UserName -eq $username } | Stop-Process -Force
        Write-Output "Killed lingering processes for $username."
    } catch {
        Write-Output "Failed to stop some processes for $username."
    }
    #Remove profile using WMI (Remove-UserProfile)
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
    #Remove the user's profile directory from C:\Users
    $profilePath = "C:\Users\$username"
    if (Test-Path $profilePath) {
        try {
            Remove-Item -Path $profilePath -Recurse -Force
            Write-Output "Profile directory for $username removed from C:\Users."
        } catch {
            Write-Output "Failed to remove profile directory for $username from C:\Users."
        }
    } else {
        Write-Output "Profile directory for $username does not exist in C:\Users."
    }
    #Remove profile registry key from HKLM (ProfileList)
    $profileRegKeyPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$sid"
    try {
        Remove-Item -Path $profileRegKeyPath -Recurse -Force -ErrorAction SilentlyContinue
        Write-Output "Registry entry for $username ($sid) removed from ProfileList."
    } catch {
        Write-Output "Failed to remove registry entry for $username ($sid)."
    }
    #Clear the last logged on user in HKLM if it's in the list
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
    #Remove user's registry from HKCU (via HKEY_USERS)
    $hkuRegKeyPath = "HKEY_USERS\$sid"
    try {
        Remove-Item -Path $hkuRegKeyPath -Recurse -Force -ErrorAction SilentlyContinue
        Write-Output "Registry entry for $username ($sid) removed from HKEY_USERS."
    } catch {
        Write-Output "Failed to remove registry entry for $username ($sid) from HKEY_USERS."
    }
}
