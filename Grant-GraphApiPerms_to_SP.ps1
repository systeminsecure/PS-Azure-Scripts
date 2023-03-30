<# Grant-GraphApiPerms_to_SP.ps1 v0.1 SystemInsecure
 --== March 30, 2023 ==--
 
Some Azure Enterprise apps (Service Principals) need additional permissions. If there is already an associated
App Registration, those additional permissions can be granted there in the Azure Portal. If the App Registration is missing, you can use 
the Microsoft Graph PowerShell Module to add those permissions to the Service Principal directly as there currently is no way
to do this throught he Azure Portal.

The user running this script will need the following roles:

  Privileged Role Administrator (needed for grants to Graph API), Application Administrator
    OR,
  Global Administrator
  
The roles can be assigned directly, or through Azure PIM. The roles MUST be ACTIVE before you run this script.

https://learn.microsoft.com/en-us/powershell/module/azuread/new-azureadapplication?view=azureadps-2.0
https://learn.microsoft.com/en-us/powershell/microsoftgraph/tutorial-grant-app-only-api-permissions?view=graph-powershell-1.0

See Errata section at bottom for prerequisites, restrictions and the changelog.
#>

# Check to see if the Microsoft.Graph powershell module is installed
foreach($module in "Microsoft.Graph.Authentication","Microsoft.Graph.Applications"){
	if (!(Get-Module -name $module)){
        	if (Get-Module -ListAvailable -Name $module) {
            		Write-Host ("> Module $($module) installed but not loaded`, importing it for use.") -ForegroundColor White
            		import-module $module 
            		if (Get-Module -name $module){
                		Write-Host  (">> Module $($module) imported successfully") -ForegroundColor Green
                	}
            	} else {
            	Write-Host (">> Module $($module) does not exist and needs to be installed first (try run: Install-Module $module -Scope CurrentUser) ") -ForegroundColor Red
        	}
    	} else {
	Write-Host  ("> Module $module already loaded") -ForegroundColor Green
    	}
}

# Interactive Authentication
Connect-MgGraph -Scopes "Application.Read.All","AppRoleAssignment.ReadWrite.All"

# Set Variables
$RoleRecords = @()
$ApplicationName = "<My Service Principal/Enterprise App Name>" # change this variable to match the SP you are working on

# Graph API Resource ID
$ResourceId=(Get-MgServicePrincipal -Filter "displayName eq 'Microsoft Graph'").Id

# Additional role IDs to add
$Roles = @("Directory.Read.All","Mail.Read","Mail.ReadBasic.All","MailboxSettings.Read","Mail.ReadBasic.Shared","email")
$AllRoles = Get-MgServicePrincipal -Filter "displayName eq 'Microsoft Graph'" -Property AppRoles | Select -ExpandProperty appRoles | Select Value,Id
foreach ($role in $AllRoles){
        if ($role.value -in $Roles){
                $myRole = [PSCustomObject] @{
                                "ResourceID" = $($ResourceId)
                                "AppRoleId" = $($role.Id)
                                "Value" = $($role.Value)
                }
        $RoleRecords = $RoleRecords + $myRole
        }
}


# Get id of enterprise app
$PrincipalId = (Get-MgServicePrincipal -Filter "displayName eq '$($ApplicationName)'").Id   #-Property AppRoles | Select -ExpandProperty appRoles |fl

# Set permission grant loop
Foreach ($record in $RoleRecords) {
    $params = @{
      "PrincipalId" = $PrincipalId
      "ResourceId" = $record.ResourceId
      "AppRoleId" = $record.AppRoleId
    }
    $params
    New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $record.ResourceId -BodyParameter $params | Format-List Id, AppRoleId, CreatedDateTime, PrincipalDisplayName, PrincipalId, PrincipalType, ResourceDisplayName
}

<# --== Errata ==--
Prerequisites needed before launching:
- Powershell 5.1 or better
- Graph API module installed (you need to do this in an elevated powershell window): > install-module Microsoft.Graph
- Permissions (or an elevated role) as listed in the header.

Restrictions
- None

To do in later versions:
- Nothing planned

Changelog:
- 0.1 Initial version. Mar 30, 2023.
#>
