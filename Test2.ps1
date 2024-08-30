# Define the usernames you want to check
$usernames = @("John.Test", "Marcus.Bonley", "An.al")

# Loop through each username to find and display their SID
foreach ($username in $usernames) {
    try {
        # Find the user's SID
        $sid = (New-Object System.Security.Principal.NTAccount($username)).Translate([System.Security.Principal.SecurityIdentifier]).Value
        Write-Output "The SID for $username is $sid"
    } catch {
        Write-Output "Failed to find SID for $username. The account might not exist."
    }
}
