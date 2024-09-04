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
            logoff (quser | Select-String $username | ForEach-Object { $_.Line.Split()[2] }) /server:localhost
            Start-Sleep -Seconds 5  # Wait for a few seconds to ensure successful logoff
            Write-Output "$username logged off successfully."
        } catch {
            Write-Output "Failed to log off $username."
        }
    }
    # Remove profile
    try {
        Write-Output "Removing user profile for $username with SID $sid..."
        $profilePath = Get-WmiObject -Class Win32_UserProfile | Where-Object { $_.SID -eq $sid } | Select-Object -ExpandProperty LocalPath
        Remove-Item -Recurse -Force $profilePath
        Write-Output "User profile removed: $profilePath"
    } catch {
        Write-Output "Failed to remove profile for $username."
    }
    # uses sid to remove the user's registry key (hklm)
    $profileRegKeyPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$sid"
    try {
        if (Test-Path $profileRegKeyPath) {
            Remove-Item -Path $profileRegKeyPath -Recurse -Force
            Write-Output "Registry entry for $username ($sid) removed from ProfileList."
        } else {
            Write-Output "Registry entry for $username ($sid) not found in ProfileList."
        }
    } catch {
        Write-Output "Failed to remove registry entry for $username ($sid)."
    }
}
