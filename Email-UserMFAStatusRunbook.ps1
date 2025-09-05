<# Email-UserMFAStatus.ps1 v0.1 2025-07-24

Gets all enabled users in Azure Entra ID and dumps out their registered MFA methods and the default method selected

See Errata section at bottom for prerequisites, restrictions, and the changelog.

#>


<# Certificate setup

$scriptpath = "C:\MFAUsage_runbook"
$CertName = "MFACheck"
$Cert = New-SelfSignedCertificate -DnsName "$($CertName).mydomain.intra" -CertStoreLocation "Cert:\CurrentUser\My" -FriendlyName "$($CertName)" -Subject "$($CertName).mydomain.intra"  -NotAfter $((Get-Date).AddMonths(36))
Get-ChildItem "Cert:\CurrentUser\My\$($Cert.thumbprint)"
Get-ChildItem "Cert:\CurrentUser\My\$($Cert.thumbprint)" | Export-Certificate -FilePath "$($scriptpath)\$($CertName).cer"

#>

$ErrorActionPreference = "Stop"

function Send-EmailWithSendGrid {
     Param
    (
        [Parameter(Mandatory=$true)]
        [string] $From,
 
        [Parameter(Mandatory=$true)]
        [String] $To,

        [Parameter(Mandatory=$false)]
        [String] $Bcc="",

        [Parameter(Mandatory=$true)]
        [string] $ApiKey,

        [Parameter(Mandatory=$true)]
        [string] $Subject,

        [Parameter(Mandatory=$true)]
        [string] $Body

    )

    $headers = @{}
    $headers.Add("Authorization","Bearer $apiKey")
    $headers.Add("Content-Type", "application/json")

    foreach ($Recipient in $To.split(",")){
        Write-Output("$Recipient")
        if ($Bcc -ne ""){
            Write-Output("bcc ::$($Bcc)::")
            $jsonRequest = [ordered]@{
                                    personalizations= @(
                                    @{to = @(@{email =  "$Recipient"})
                                    bcc = @(@{email =  "$Bcc"})
                                        subject = "$Subject" })
                                        from = @{email = "$From"}
                                        content = @( @{ type = "text/html"
                                                    value = "$Body" }
                                        )} | ConvertTo-Json -Depth 10
        } else {

            $jsonRequest = [ordered]@{
                                    personalizations= @(
                                    @{to = @(@{email =  "$Recipient"})
                                        subject = "$Subject" })
                                        from = @{email = "$From"}
                                        content = @( @{ type = "text/html"
                                                    value = "$Body" }
                                        )} | ConvertTo-Json -Depth 10

        }

            Invoke-RestMethod   -Uri "https://api.sendgrid.com/v3/mail/send" -Method Post -Headers $headers -Body $jsonRequest -Verbose

    }
}

function Format-BoolCell {
    param($value)
    switch ($value) {
        $true {return "<b>True</b>"}
        $false {return "False"}
        "Disabled" {return "<b>Disabled</b>"}
        "Enabled" {return "Enabled"}
        default {return $value}
    }
}

# variables
[string]$tenantId = "<insert tenant id here>"
[string]$scriptversion = "v0.1"

# email variables
[string]$msgFrom    = "report@mydomain.intra"
[string]$MsgTo      = "recipient@mydomain.intra"
[string]$MailSubject = "Multifactor method Registration Report for $((Get-Date).ToString("yyyy-MM-dd"))"


if ($PSPrivateMetadata.JobId) {
    [string]$appId = Get-AutomationVariable -Name 'MFACheck_identity'
    [System.Security.Cryptography.X509Certificates.X509Certificate]$Certificate = (Get-AutomationCertificate -Name 'MFACheck_certificate')
    if ($SendGridtoken -eq $null) {$SendGridtoken = Get-AutomationVariable -Name 'SendGridtoken'}

} else {
    #Local variables
    #For testing if required
}

# initiate auth
Import-Module Microsoft.Graph.Authentication, Microsoft.Graph.Reports, Microsoft.Graph.Users
$null = Connect-MgGraph -TenantId $TenantId -CertificateThumbprint $Certificate.Thumbprint -ClientId $appId
#Get-MgContext


#stopwatch
$watch = New-Object System.Diagnostics.Stopwatch
$watch.reset()
$watch.Start()
Write-Output "[$((Get-Date).ToString("yyyy-MM-dd HH:mm:ss"))] Email-UserMFAStatus.ps1 $($scriptversion) Script started on $($env:COMPUTERNAME).$($env:USERDNSDOMAIN)."

#Get all Azure users
$filter = "accountEnabled eq true"
#$users = Get-MgUser -Filter $filter -All
$users = Get-MgUser -Filter $filter -All -Property Id,UserPrincipalName,DisplayName,Department,OfficeLocation,jobTitle,EmployeeType | sort UserPrincipalName
$usersNL = Get-MgUser -Filter 'assignedLicenses/$count eq 0' -ConsistencyLevel eventual -CountVariable licensedUserCount -All | Select UserPrincipalName #unlicensed users
$count = 1
$results=@();
Write-Output  "`nRetreived $($users.Count) enabled users";


# HTML report start
$html = @"
<html><body>
<h2>MFA Registration Report</h2>
<p>Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
<table border="1" cellpadding="4" cellspacing="0">
<tr>
<th>UserPrincipalName</th><th>DisplayName</th><th>Title</th><th>Department</th><th>Office</th><th>Licensed</th>
<th>Admin</th><th>MFA Status</th><th>Default Method</th>
<th>Email</th><th>Authenticator App</th><th>Phone/SMS</th><th>OATH</th><th>FIDO2</th><th>Hello</th><th>TAP</th>
</tr>
"@

foreach ($user in $users) {
    Write-Output "Processing $($user.UserPrincipalName)"

    $methods = Get-MgUserAuthenticationMethod -UserId $user.Id -ErrorAction SilentlyContinue
    $defaultMFA = $null

    if ($methods.Count -gt 1) {
        $defaultMFA = Get-MgReportAuthenticationMethodUserRegistrationDetail -UserRegistrationDetailsId $user.Id -ErrorAction SilentlyContinue
    }

    $mfaStatus = "Disabled"
    $flags = @{
        Email   = $false
        App     = $false
        Phone   = $false
        OATH    = $false
        FIDO2   = $false
        Hello   = $false
        TAP     = $false
        Default = ""
        Admin   = $false
    }

    foreach ($method in $methods) {
        switch ($method.AdditionalProperties["@odata.type"]) {
            "#microsoft.graph.emailAuthenticationMethod"         { $flags.Email = $true; $mfaStatus = "Enabled" }
            "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod" { $flags.App = $true; $mfaStatus = "Enabled" }
            "#microsoft.graph.phoneAuthenticationMethod"         { $flags.Phone = $true; $mfaStatus = "Enabled" }
            "#microsoft.graph.softwareOathAuthenticationMethod"  { $flags.OATH = $true; $mfaStatus = "Enabled" }
            "#microsoft.graph.fido2AuthenticationMethod"         { $flags.FIDO2 = $true; $mfaStatus = "Enabled" }
            "#microsoft.graph.windowsHelloForBusinessAuthenticationMethod" { $flags.Hello = $true; $mfaStatus = "Enabled" }
            "#microsoft.graph.temporaryAccessPassAuthenticationMethod"     { $flags.TAP = $true; $mfaStatus = "Enabled" }
        }
    }

    if ($defaultMFA -and $defaultMFA.UserPreferredMethodForSecondaryAuthentication) {
        switch ($defaultMFA.UserPreferredMethodForSecondaryAuthentication) {
            "push" { $flags.Default = "Authenticator App" }
            "oath" { $flags.Default = "OATH" }
            default { $flags.Default = $defaultMFA.UserPreferredMethodForSecondaryAuthentication }
        }
        $flags.Admin = $defaultMFA.IsAdmin
    }

    $licensed = if ($user.UserPrincipalName -in $unlicensed) { "No" } else { "Yes" }

$html += "<tr><td>$($user.UserPrincipalName)</td><td>$($user.DisplayName)</td><td>$($user.JobTitle)</td><td>$($user.Department)</td><td>$($user.OfficeLocation)</td><td>$licensed</td><td>$(Format-BoolCell $flags.Admin)</td><td>$(Format-BoolCell $mfaStatus)</td><td>$($flags.Default)</td><td>$(Format-BoolCell $flags.Email)</td><td>$(Format-BoolCell $flags.App)</td><td>$(Format-BoolCell $flags.Phone)</td><td>$(Format-BoolCell $flags.OATH)</td><td>$(Format-BoolCell $flags.FIDO2)</td><td>$(Format-BoolCell $flags.Hello)</td><td>$(Format-BoolCell $flags.TAP)</td></tr>"
}

$html += "</table></body></html>"


# Send report
$MailParams = @{
    From    = $MsgFrom
    To      = $MsgTo
    ApiKey  = "$SendGridtoken"
    Subject = $MailSubject
    Body    = $html
}

Send-EmailWithSendGrid @MailParams

#stopwatch
Write-Output ("[Elapsed time]: $($watch.Elapsed)")
$watch.reset() #stopwatch stop and reset
Write-Output "[$((Get-Date).ToString("yyyy-MM-dd HH:mm:ss"))] Script ended."

<# --== Errata ==--

Prerequisites needed before launching:
- Powershell 5.1 or better
- Azure App Registration with the following rights granted:
   > Microsoft Graph
     - User.Read.All
     - AuditLog.Read.All
     - UserAuthenticationMethod.Read.All
- Update variables with $tenantId, and automation variables/certifictes for appId and certificate before running first.

Restrictions
- None

To do in later versions:
- Send out reminders to the people identified as having no MFA.

Changelog:
- 0.1 Initial version for use in a runbook 2025-07-24
#>
