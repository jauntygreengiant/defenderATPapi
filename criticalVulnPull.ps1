# Much of this was built using the Microsoft documentation for the DefenderATP API, 
# which can be found here: https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/apis-intro
#
# Additional insipration was taken from JordanTheITGuy's blog post on the DefenderATP API, which can be found here: 
# https://jordantheitguy.com/security/query-defender-for-Endpoint-vulnerability-info-part-1
#
# This script is designed to pull all vulnerabilities with a CVSS score of 9 or higher from the DefenderATP API, and export them to an Excel file.

$tenantId = "xxxxxx"
$appId = "xxxxx"
$appSecret = "xxxxx"

# Build auth response token to DefenderATP API
$resourceAppIdUri = "https://api-gcc.securitycenter.microsoft.us/"
$authUri = "https://login.microsoftonline.com/$tenantId/oauth2/token"
$authBody = [Ordered] @{
    resource = $resourceAppIdUri
    client_id = $appId
    client_secret = $appSecret
    grant_type = "client_credentials"
}
$authResponse = Invoke-RestMethod -Method Post -Uri $authUri -Body $authBody -ErrorAction Stop
# Get the access token. A recommended practice is to seperate the token from the rest of the response, but for simplicity we'll use the entire response.
$token = $authResponse.access_token

# Build the request headers for the DefenderATP API
$headers = @{
    'Content-Type'  = 'application/json'
    Accept = 'application/json'
    Authorization = "Bearer $token"
}

# Get all vulnerabilities with a CVSS score of 9 or higher baeed on the CVSS v3 score and SOP
$vulnUrl = "https://api-gcc.securitycenter.microsoft.us/api/vulnerabilities?`$filter=cvssV3 ge 9"
$vulnResponse = Invoke-RestMethod -Method Get -Uri $vulnUrl -Headers $headers -ErrorAction Stop

# Convert 'value'from ODATA to JSON, then convert JSON to PowerShell object. For some reason vulnerability is ODATA and not explicit JSON.
$vulnData = ($vulnResponse.value | ConvertTo-JSON) | ConvertFrom-Json

# Install the ImportExcel module if not already installed
if (!(Get-Module -ListAvailable -Name ImportExcel)) {
    Install-Module -Name ImportExcel -Force -AllowClobber
}

# Export the data to an Excel file, only including vulnerabilities with exposed machines, and only the columns we want. Use 'split' to include only text after 'Remediation:'
# This is needed because the ODATA calls do not allow for sorrting on all parameters, and the API does not allow for sorting on the 'exposedMachines' parameter. Thus, we pull all and sort in PowerShell
$vulnData | Where-Object { $_.exposedMachines -ne 0 } | Select-Object @{Name='Vulnerability'; Expression={$_.name}}, @{Name='Operating System'; Expression={$_.operatingSystem}}, @{Name='Hostname'; Expression={$_.exposedMachines}}, @{Name='Port'; Expression={$_.port}}, @{Name='Exploit'; Expression={$_.exploitVerified}}, @{Name='Remediation'; Expression={($_.description -split 'Remediation:')[1]}}, @{Name='CVSS'; Expression={$_.cvssV3}}, @{Name='Links'; Expression={$_.links}}, @{Name='Status'; Expression={$_.status}}, @{Name='Problem Ticket ID'; Expression={$_.problemTicketId}} | Export-Excel -Path ".\vulnData.xlsx" -TableStyle Light1