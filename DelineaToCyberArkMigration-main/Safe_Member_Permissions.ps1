#Define the path and filename for the log file
$logFilePath = "C:\Users\DELL E6440\OneDrive\Desktop\add_members.log" #Change Me

# Set the URI for the token endpoint
$uri = "https://aam4326.my.idaptive.app/oauth2/platformtoken" #Change Me

# Set the URI for PCloud
$uri2 = "https://clango-ispss.privilegecloud.cyberark.cloud/PasswordVault/API/Safes/$safeUrlId/Members/" #Change Me

# Set the Location of CSV {Make sure that the CSV is stored in the local drive (onedrive and cloud is not supported)}
$csv = "D:\Test1.csv" #Change Me

# Log the start time
$StartTime = (Get-Date).ToString("dd/MM/yyyy HH:mm:ss tt")
$StartLogMessage = "$StartTime - Script started"
Add-Content -Path $logFilePath -Value $StartLogMessage
Write-Host $StartLogMessage

# Prompt user to enter credentials
$creds = Get-Credential

#Use the credentials entered by the user to retrieve a token
$token = ""
$response = Invoke-RestMethod "$uri" -Method Post -Body @{
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


#Read the CSV file and iterate over each row
Import-Csv -Path "$csv"  | ForEach-Object {
    
    # Write the log message to the log file and console
    $timestamp = Get-Date -Format "dd/MM/yyyy HH:mm:ss tt"
    $logMessage = "$timestamp - Copying data from CSV file"
    Add-Content -Path $logFilePath -Value "$logMessage"
    Write-Host $logMessage
 
    $safeName = $_."CyberArk Safe"
    $userName = $_."AD User"
    $type = $_."User/Group/Role"
    $permission1 = $_."Delinea Folder Permissions"
    $permission2 = $_."Delinea Secret Permissions"
    if ($Permission1 -eq "View/Add Secret/Edit/Owner" -and $permission2 -eq "List/View/Edit/Owner" ) {
               $Permissionsset = @{
                                 useAccounts = $true
                                 retrieveAccounts = $true
                                 listAccounts = $true
                                 addAccounts = $true
                                 updateAccountContent = $true
                                 updateAccountProperties = $true
                                 initiateCPMAccountManagementOperations = $true
                                 specifyNextAccountContent = $true
                                 renameAccounts = $true
                                 deleteAccounts = $true
                                 unlockAccounts = $true
                                 ManageSafe = $true
                                 ViewSafemembers = $true
                                 viewauditlog = $true
                                 backupsafe = $true
                                 managesafemembers = $true
                                }
                                                        }
    elseif ($Permission1 -eq "View/Add Secret/Edit/Owner" -and $permission2 -eq "List/View/Edit") {
               $Permissionsset = @{
                                 useAccounts = $true
                                 retrieveAccounts = $true
                                 listAccounts = $true
                                 updateAccountContent = $true
                                 updateAccountProperties = $true
                                 unlockAccounts = $true
                                 renameAccounts = $true 
                                 initiateCPMAccountManagementOperations = $true
                                 specifyNextAccountContent = $true
                                 ManageSafe = $true
                                 ViewSafemembers = $true
                                 viewauditlog = $true
                                 backupsafe = $true
                                 addaccounts = $true
                                 managesafemembers = $true
                                }
                                                      }
    elseif ($Permission1 -eq "View/Add Secret/Edit/Owner" -and $permission2 -eq "List/View") {
               $Permissionsset = @{
                                 useAccounts = $true
                                 retrieveAccounts = $true
                                 listAccounts = $true
                                 ManageSafe = $true
                                 ViewSafemembers = $true
                                 viewauditlog = $true
                                 backupsafe = $true
                                 addaccounts = $true
                                 managesafemembers = $true
                                 
                                }
                                                }
    elseif ($Permission1 -eq "View/Add Secret/Edit/Owner" -and $permission2 -eq "List") {
               $Permissionsset = @{
                                 listAccounts = $true
                                 ManageSafe = $true
                                 ViewSafemembers = $true
                                 viewauditlog = $true
                                 backupsafe = $true
                                 addaccounts = $true
                                 managesafemembers = $true
                                 
                                }
                                                }
    elseif ($Permission1 -eq "View/Add Secret/Edit" -and $permission2 -eq "List/View/Edit/Owner") {
               $Permissionsset = @{
                                 useAccounts = $true
                                 retrieveAccounts = $true
                                 listAccounts = $true
                                 addAccounts = $true
                                 updateAccountContent = $true
                                 updateAccountProperties = $true
                                 initiateCPMAccountManagementOperations = $true
                                 specifyNextAccountContent = $true
                                 renameAccounts = $true
                                 deleteAccounts = $true
                                 unlockAccounts = $true
                                 ManageSafe = $true
                                 ViewSafemembers = $true
                                 viewauditlog = $true
                                 backupsafe = $true
                                 
                                }
                                                }
    elseif ($Permission1 -eq "View/Add Secret/Edit" -and $permission2 -eq "List/View/Edit") {
               $Permissionsset = @{
                                 useAccounts = $true
                                 retrieveAccounts = $true
                                 listAccounts = $true
                                 updateAccountContent = $true
                                 updateAccountProperties = $true
                                 unlockAccounts = $true
                                 renameAccounts = $true 
                                 initiateCPMAccountManagementOperations = $true
                                 specifyNextAccountContent = $true
                                 ManageSafe = $true
                                 ViewSafemembers = $true
                                 viewauditlog = $true
                                 backupsafe = $true
                                 addaccounts = $true
                                }
                                                }
    elseif ($Permission1 -eq "View/Add Secret/Edit" -and $permission2 -eq "List/View") {
               $Permissionsset = @{
                                 useAccounts = $true
                                 retrieveAccounts = $true
                                 listAccounts = $true
                                 ManageSafe = $true
                                 ViewSafemembers = $true
                                 viewauditlog = $true
                                 backupsafe = $true
                                 addaccounts = $true
                                }
                                                }
    elseif ($Permission1 -eq "View/Add Secret/Edit" -and $permission2 -eq "List") {
               $Permissionsset = @{
                                 listAccounts = $true
                                 ManageSafe = $true
                                 ViewSafemembers = $true
                                 viewauditlog = $true
                                 backupsafe = $true
                                 addaccounts = $true
                                }
                                                }
    elseif ($Permission1 -eq "View/Add Secret" -and $permission2 -eq "List/View/Edit/Owner") {
               $Permissionsset = @{
                                 useAccounts = $true
                                 retrieveAccounts = $true
                                 listAccounts = $true
                                 addAccounts = $true
                                 updateAccountContent = $true
                                 updateAccountProperties = $true
                                 initiateCPMAccountManagementOperations = $true
                                 specifyNextAccountContent = $true
                                 renameAccounts = $true
                                 deleteAccounts = $true
                                 unlockAccounts = $true
                                }
                                                }
    elseif ($Permission1 -eq "View/Add Secret" -and $permission2 -eq "List/View/Edit") {
               $Permissionsset = @{
                                 useAccounts = $true
                                 retrieveAccounts = $true
                                 listAccounts = $true
                                 updateAccountContent = $true
                                 updateAccountProperties = $true
                                 unlockAccounts = $true
                                 renameAccounts = $true 
                                 initiateCPMAccountManagementOperations = $true
                                 specifyNextAccountContent = $true
                                 addaccounts = $true
                                }
                                                }
    elseif ($Permission1 -eq "View/Add Secret" -and $permission2 -eq "List/View") {
               $Permissionsset = @{
                                 useAccounts = $true
                                 retrieveAccounts = $true
                                 listAccounts = $true
                                 addaccounts = $true
                                }
                                                }
    elseif ($Permission1 -eq "View/Add Secret" -and $permission2 -eq "List") {
               $Permissionsset = @{
                                 listAccounts = $true
                                 addaccounts = $true
                                }
         
                                                }
    elseif ($Permission2 -eq "List/View/Edit/Owner" -and $permission1 -eq "") {
               $Permissionsset = @{
                                 useAccounts = $true
                                 retrieveAccounts = $true
                                 listAccounts = $true
                                 addAccounts = $true
                                 updateAccountContent = $true
                                 updateAccountProperties = $true
                                 initiateCPMAccountManagementOperations = $true
                                 specifyNextAccountContent = $true
                                 renameAccounts = $true
                                 deleteAccounts = $true
                                 unlockAccounts = $true  
                                }
                                                        }
    elseif ($Permission2 -eq "List/View/Edit" -and $permission1 -eq "") {
               $Permissionsset = @{
                                 useAccounts = $true
                                 retrieveAccounts = $true
                                 listAccounts = $true
                                 updateAccountContent = $true
                                 updateAccountProperties = $true
                                 unlockAccounts = $true
                                 renameAccounts = $true 
                                 initiateCPMAccountManagementOperations = $true
                                 specifyNextAccountContent = $true
                                }
                                                      }
    elseif ($Permission2 -eq "List/View" -and $permission1 -eq "") {
               $Permissionsset = @{
                                 useAccounts = $true
                                 retrieveAccounts = $true
                                 listAccounts = $true
                                }
                                                }
    
    elseif ($Permission2 -eq "List" -and $permission1 -eq "") {
               $Permissionsset = @{
                                 listAccounts = $true
                                 }
                                                }
    elseif ($Permission1 -eq "View/Add Secret/Edit/Owner" -and $permission2 -eq "") {
               $Permissionsset = @{
                                 ManageSafe = $true
                                 ViewSafemembers = $true
                                 viewauditlog = $true
                                 backupsafe = $true
                                 addaccounts = $true
                                 managesafemembers = $true
                                }
                                                        }
    elseif ($Permission1 -eq "View/Add Secret/Edit" -and $permission2 -eq "") {
               $Permissionsset = @{
                                 ManageSafe = $true
                                 ViewSafemembers = $true
                                 viewauditlog = $true
                                 backupsafe = $true
                                 addaccounts = $true
                                }
                                                      }
    elseif ($Permission1 -eq "View/Add Secret" -and $permission2 -eq "") {
               $Permissionsset = @{
                                 addaccounts = $true
                                }
                                                }

    #Build the request body
    $body = @{
        MemberType = "$type"
        MemberName = "$userName"
        Permissions = $Permissionsset
 
   } | ConvertTo-Json


    try 
    {
        #Send the request to add the group to the safe
        $safeUrlId = $safeName
        $add_member_response = Invoke-RestMethod "$uri2" -Method Post -Body $body -Headers $headers -ContentType "application/json"
        $logMessage = "Successfully added AD $type '$userName' to safe '$safeName' with permissions"
    }

    catch 
    {
        #If the request fails, log the error message
        $logMessage = "Failed to add AD $type '$userName' to safe '$safeName': $_"
    }
    #Generate a timestamp for the log message
    $LogDate = (Get-Date).tostring("yyyyMMdd")
    $TimeStamp = (Get-Date).toString("dd/MM/yyyy HH:mm:ss tt")
    $Line = "$TimeStamp - $logMessage"

    #Format the log message and write it to the log file and console
    Add-Content -Path $logFilePath -Value "$Line"
    Write-Host $Line
}

# Log the end time
$EndTime = (Get-Date).ToString("dd/MM/yyyy HH:mm:ss tt")
$EndLogMessage = "$EndTime - Script ended"
Add-Content -Path $logFilePath -Value $EndLogMessage
Write-Host $EndLogMessage

#Add a newline to the log file to separate the current execution from future ones
Add-Content -Path $logFilePath -Value "`n"