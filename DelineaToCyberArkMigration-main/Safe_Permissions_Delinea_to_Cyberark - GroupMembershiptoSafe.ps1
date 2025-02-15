#This script is used to add groups/roles to specific safes with mapped permissions in Pcloud

#Define the path and filename for the log file
$logFilePath = "C:\Users\DELL\Documents\logs\adress.log" #Change Me

# Set the URI for the token endpoint
$uri = "https://aam4326.my.idaptive.app/oauth2/platformtoken" #Change Me

# Set the URI for PCloud
$uri2 = "https://clango-ispss.privilegecloud.cyberark.cloud/PasswordVault/API/Safes/$safeUrlId/Members/" #Change Me

# Set the Location of CSV {Make sure that the CSV is stored in the local drive (onedrive and cloud is not supported)}
$csv = "C:\Users\DELL\Desktop\Test_SafePermission.csv" #Change Me

# Log the start time
$StartTime = (Get-Date).ToString("dd/MM/yyyy HH:mm:ss tt")
$StartLogMessage = "$StartTime - Script started"
Add-Content -Path $logFilePath -Value $StartLogMessage
Write-Host $StartLogMessage

# Prompt user to enter credentials
$creds = Get-Credential


#Use the credentials entered by the user to retrieve a token
$token = ""
$response = Invoke-RestMethod "$uri" -Method POST -Body @{
        client_id = $creds.UserName
        client_secret = $creds.GetNetworkCredential().Password
        grant_type = "client_credentials"
} -ContentType "application/x-www-form-urlencoded"
$token = $response.access_token


if (-not [string]::IsNullOrEmpty($token)) {
    Write-Host "Token obtained successfully: $token"
    Write-Host "Script is continuing..."
} else {
    Write-Host "Failed to obtain the token. Script will stop."
    Exit
}

# Log the login time
$LoginTime = (Get-Date).ToString("dd/MM/yyyy HH:mm:ss tt")
$LoginLogMessage = "$LoginTime - Logged in"
Add-Content -Path $logFilePath -Value $LoginLogMessage
Write-Host $LoginLogMessage


#Create an object to hold the Authorization header
$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$headers.Add("Authorization", "Bearer $token")

# Log the time when the script starts reading from the CSV file
$CSVReadTime = (Get-Date).ToString("dd/MM/yyyy HH:mm:ss tt")
$CSVReadLogMessage = "$CSVReadTime - Started reading from CSV file"
Add-Content -Path $logFilePath -Value $CSVReadLogMessage
Write-Host $CSVReadLogMessage


#Read the CSV file and iterate over each row #Change Me
Import-Csv -Path $csv  | ForEach-Object {
    
    # Write the log message to the log file and console
    $timestamp = Get-Date -Format "dd/MM/yyyy HH:mm:ss tt"
    $logMessage = "$timestamp - Copying data from CSV file"
    Add-Content -Path $logFilePath -Value "$logMessage"
    Write-Host $logMessage
 
    $safeName = $_."CyberArk Safe"
    $groupName = $_."CyberArk GroupName"
    $type = $_."Role"

    #check if the groupname has owner in it

    
    #Permissionset for VaultAdmins
     if  ($groupName -eq "Privilege Cloud Administrators") {
               $Permissionsset = @{
                                 ViewSafemembers = $true
                                 manageSafeMembers = $true
                                 }
      
      
                                                           }

     #check if the groupname has owner in it
    elseif ($groupName -eq "$safeName-Owner") {
        $PermissionsSet = @{
                          useAccounts                             = $true
                          retrieveAccounts                        = $true
                          listAccounts                            = $true
                          addAccounts                             = $true
                          updateAccountContent                    = $true
                          updateAccountProperties                 = $true
                          initiateCPMAccountManagementOperations  = $true
                          specifyNextAccountContent               = $true
                          renameAccounts                          = $true
                          deleteAccounts                          = $true
                          unlockAccounts                          = $true
                          ManageSafe                              = $true
                          ViewSafemembers                         = $true
                          viewauditlog                            = $true
                          backupsafe                              = $true
                          accessWithoutConfirmation               = $true
                          createFolders                           = $true
                          deleteFolders                           = $false
                          moveAccountsAndFolders                  = $true
                          requestsAuthorizationLevel1            = $true
                          requestsAuthorizationLevel2            = $false
                          }
                                     }

    #Permissionset for Managers
    elseif ($groupName -eq "$safeName-Manager") {
               $Permissionsset = @{
                                 useAccounts = $true
                                 retrieveAccounts = $true
                                 listAccounts = $true
                                 addAccounts = $true
                                 updateAccountContent = $true
                                 updateAccountProperties = $true
                                 unlockAccounts = $true
                                 renameAccounts = $true 
                                 ViewSafemembers = $true
                                 viewauditlog = $true
                                 requestsAuthorizationLevel1 = $true
                                 requestsAuthorizationLevel2 = $false
                                 }
                                            }
    #Permissionset for Users
    elseif ($groupName -eq "$safeName-User") {
               $Permissionsset = @{
                                 useAccounts = $true
                                 retrieveAccounts = $true
                                 listAccounts = $true
                                 }
                                            }


    #Permissionset for Auditors
    elseif  ($groupName -eq "$safeName-Auditor") {
               $Permissionsset = @{
                                 listAccounts = $true
                                 }
                                           }

    #Permissionset for Owners 
    elseif ($groupName -eq "$safeName-Owner") {
        $PermissionsSet = @{
                          useAccounts                             = $true
                          retrieveAccounts                        = $true
                          listAccounts                            = $true
                          addAccounts                             = $true
                          updateAccountContent                    = $true
                          updateAccountProperties                 = $true
                          initiateCPMAccountManagementOperations  = $true
                          specifyNextAccountContent               = $true
                          renameAccounts                          = $true
                          deleteAccounts                          = $true
                          unlockAccounts                          = $true
                          ManageSafe                              = $true
                          ViewSafemembers                         = $true
                          viewauditlog                            = $true
                          backupsafe                              = $true
                          accessWithoutConfirmation               = $true
                          createFolders                           = $true
                          deleteFolders                           = $false
                          moveAccountsAndFolders                  = $true
                          requestsAuthorizationLevel1            = $true
                          requestsAuthorizationLevel2            = $false
                          }
                                     }
     

     #Note - The permissionset will be according to group mapping of the environment.


        
     #Build the Request Body
     $body = @{
         MemberType  = "$type"
         MemberName  = "$groupName"
         Permissions = $Permissionsset

    } | ConvertTo-Json



    try 
    {
         # Send the request to add the group to the safe
        $safeUrlId = $safeName
        $add_member_response = Invoke-RestMethod $uri2 -Method POST -Body $body -Headers $headers -ContentType "application/json" #Change Me
        $logMessage = "Successfully added CyberArk Group '$groupName' to safe '$safeName' with permissions"
    }

    catch
    {
        $logMessage = "Failed to add AD $type '$groupName' to safe '$safeName': $_"
    }
    #Generate a timestamp for the log message
    $LogDate = (Get-Date).tostring("yyyyMMdd")
    $TimeStamp = (Get-Date).toString("dd/MM/yyyy HH:mm:ss tt")
    $Line = "$TimeStamp - $logMessage"

    #Format the log message and write it to the log file and console
    Add-Content -Path $logFilePath -Value "$Line"
    Write-Host $Line
    }


    #Generate a timestamp for the log message
    $LogDate = (Get-Date).tostring("yyyyMMdd")
    $TimeStamp = (Get-Date).toString("dd/MM/yyyy HH:mm:ss tt")
    $Line = "$TimeStamp - $logMessage"

    #Format the log message and write it to the log file and console
    Add-Content -Path $logFilePath -Value "$Line"
    Write-Host $Line

    
# Log the end time
$EndTime = (Get-Date).ToString("dd/MM/yyyy HH:mm:ss tt")
$EndLogMessage = "$EndTime - Script ended"
Add-Content -Path $logFilePath -Value $EndLogMessage
Write-Host $EndLogMessage

#Add a newline to the log file to separate the current execution from future ones
Add-Content -Path $logFilePath -Value "`n"