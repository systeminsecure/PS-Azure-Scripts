<# Grant-GraphApiPerms_to_ServicePrincipal.ps1 v0.2.1 2024-10-29 systeminsecure
 
Some Azure Enterprise apps (Service Principals) need additional permissions. If there is already an associated
App Registration, those additional permissions can be granted there in the Azure Portal. If the App Registration is missing, you can use 
the Microsoft Graph PowerShell Module to add those permissions to the Service Principal directly as there currently is no way
to do this through the Azure Portal.

The user running this script will need the following roles:

  Privileged Role Administrator (needed for grants to Graph API) + Application Administrator
    OR,
  Global Administrator
  
The roles can be assigned directly, or through Azure PIM. The roles MUST be ACTIVE before you run this script.

https://learn.microsoft.com/en-us/powershell/module/azuread/new-azureadapplication?view=azureadps-2.0
https://learn.microsoft.com/en-us/powershell/microsoftgraph/tutorial-grant-app-only-api-permissions?view=graph-powershell-1.0

See Errata section at bottom for prerequisites, restrictions and the changelog.
#>



# Check to see if the Microsoft.Graph powershell module is installed
foreach($module in "Microsoft.Graph.Authentication","Microsoft.Graph.Applications","MSAL.PS"){
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

#List scopes in session
$Context = Get-MgContext 
$Context.Account
$Context.AuthType
$Context.Scopes

# Set Variables
$ServicePrincipalDisplayName = "<name of account here>"
$Roles = @(
    "Exchange.ManageAsApp"
)
$RoleAPI = "Office 365 Exchange Online" 
#for "Exchange.ManageAsApp", the role API needs to be set to "Office 365 Exchange Online"
#for "UserAuthenticationMethod.ReadWrite.All" the role API needs to be set to "Microsoft Graph"

# Get id of enterprise app service principal
$AppPrincipal = (Get-MgServicePrincipal -Filter "displayName eq '$($ServicePrincipalDisplayName)'")

# Additional Graph role IDs to add
$GraphPrincipal = Get-MgServicePrincipal -Filter "displayName eq '$($RoleAPI)'"
$oAppRole = $GraphPrincipal.AppRoles | Where-Object {($_.Value -in $Roles) -and ($_.AllowedMemberTypes -contains "Application")}


#Add roles to AppPrincipal
foreach($AppRole in $oAppRole)
{
  $oAppRoleAssignment = @{
    "PrincipalId" = $AppPrincipal.Id
    "ResourceId" = $GraphPrincipal.Id
    "AppRoleId" = $AppRole.Id
  }
  
  if($AppRole.Id -notin (Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $oAppRoleAssignment.PrincipalId).AppRoleId){
    New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $oAppRoleAssignment.PrincipalId -BodyParameter $oAppRoleAssignment -Verbose
  } else {
    echo "$($AppRole.Value) already exists in $($ServicePrincipalDisplayName)"
  }
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
- 0.2 bugfixes and simplify script. May 17, 2024
- 0.2.1 Added documentation Oct 29, 2024
#>
