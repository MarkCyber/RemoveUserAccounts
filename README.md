# RemoveWindowsAccounts
After various tests on different scripts and ways to implement them, the [AccountRemovalFinal.ps1](https://github.com/MarkCyber/RemoveWindowsAccounts/blob/main/AccountRemovalFinal.ps1) script has been what works best. This not only removes the user from the login screen, but essentially removes their entire profile from the machine. This also avoids WMIC usage to prevent any potential issues.

## How to run:
1. Download the script from [here](https://github.com/MarkCyber/RemoveWindowsAccounts/blob/main/AccountRemovalFinal.ps1) and then open it in a text editor.
2. Modify the code to include the usernames of the profiles you would like to remove.
3. You may then navigate to the directory the script is located in, and run it that way.
   3.1. You may also run the script through a scheduled task.
   3.2. You may also run the script through windows sccm (software center).



