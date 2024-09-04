$usernames = @("John.doesNotexistttt", "Test.Account", "testingthis")
$loggedOnUsers = Get-WmiObject -Class Win32_ComputerSystem | Select-Object -ExpandProperty UserName
foreach ($username in $usernames) {
    # Find SID
    $sid = (New-Object System.Security.Principal.NTAccount($username)).Translate([System.Security.Principal.SecurityIdentifier]).Value
    if ($loggedOnUsers -contains $username) {
        logoff (quser | Select-String $username | ForEach-Object { $_.Line.Split()[2] }) /server:localhost
        Start-Sleep -Seconds 5  # Wait for a few seconds to ensure a successful logoff
    }
    #Remove profile
    try {
        Write-Output "Removing user profile for $username with SID $sid..."
        $profilePath = Get-WmiObject -Class Win32_UserProfile | Where-Object { $_.SID -eq $sid } | Select-Object -ExpandProperty LocalPath
        Remove-Item -Recurse -Force $profilePath
        Write-Output "User profile removed: $profilePath"
    } catch {
        Write-Output "Failed to remove profile for $username"
    }
}
