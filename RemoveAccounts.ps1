# THIS IS A WORK IN PROGRESS

# Define the usernames to be removed
$usernames = @("John.Test", "Marcus.Bonley", "Test.acc")
 
# Get the list of currently logged on users
$loggedOnUsers = Get-WmiObject -Class Win32_ComputerSystem | Select-Object -ExpandProperty UserName
 
# Loop through each username
foreach ($username in $usernames) {
    # Find the user's SID
    $sid = (New-Object System.Security.Principal.NTAccount($username)).Translate([System.Security.Principal.SecurityIdentifier]).Value
 
    # Check if the user is currently logged in
    if ($loggedOnUsers -contains $username) {
        Write-Output "$username is currently logged on. Logging them off..."
 
        # Log off the user
        logoff (quser | Select-String $username | ForEach-Object { $_.Line.Split()[2] }) /server:localhost
 
        Start-Sleep -Seconds 5  # Wait for a few seconds to ensure the user is logged off
    }
 
    # Remove the user's profile
    try {
        Write-Output "Removing user profile for $username with SID $sid..."
        $profilePath = Get-WmiObject -Class Win32_UserProfile | Where-Object { $_.SID -eq $sid } | Select-Object -ExpandProperty LocalPath
        Remove-Item -Recurse -Force $profilePath
        Write-Output "User profile removed: $profilePath"
    } catch {
        Write-Output "Failed to remove profile for $username"
    }
}
