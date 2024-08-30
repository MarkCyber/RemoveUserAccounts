$localuserprofiles = Get-WmiObject -Class Win32_UserProfile | Select-Object localPath | Where{_.LocalPath -notlike "*$env:SystemRoot*"}
$excludeduserpath = "Administrator"
$profilestodelete = $localUserProfiles | where-object($_.Localpath - notlike "*$excludeduserpath*"}
Foreach($deletedprofile in $profilestodelete)
   {
   write-host $deletedprofile
(Get-Item $deletedprofile.localPath).Delete()
   }



