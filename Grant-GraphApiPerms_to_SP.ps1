<# Grant-GraphApiPerms_to_ServicePrincipal.ps1 v0.3 2025-04-17
 
Some Azure Enterprise apps (Service Principals) need additional permissions. If there is already an associated
App Registration, those additional permissions can be granted there in the Azure Portal. If the App Registration is missing, you can use 
the Microsoft Graph PowerShell Module to add those permissions to the Service Principal directly as there currently is no way
to do this through the Azure Portal.

The user running this script will need the following roles:

  Privileged Role Administrator (needed for consent grants in Graph API) + Application Administrator
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
Write-Output " >> You are this person with these scopes..."
$Context = Get-MgContext 
$Context.Account
$Context.AuthType
$Context.Scopes

# Set Variables
Write-Output " >> Retrieving list of Service Principals to choose from..."
$ServicePrincipal = (Get-MgServicePrincipal -All | sort  DisplayName  | Out-GridView -Title "Choose Service Principal" -OutputMode Single)
if($ServicePrincipal.length -eq $null -or $ServicePrincipal.length -eq 0){
    break
}
Write-output ("`n$($ServicePrincipal.Displayname) selected.")

#list the permissions the SP currently has
[array]$AssignedAppRoles = @()
[array]$CurrentAppRoles = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $ServicePrincipal.Id
foreach($role in ($CurrentAppRoles | select Id,ResourceDisplayName,AppRoleId)){
    $GraphPrincipal = Get-MgServicePrincipal -Filter "displayName eq '$($role.ResourceDisplayName)'"
    $CurrentAppRoles += ($GraphPrincipal.AppRoles | ?{$_.Id -eq $role.AppRoleId} | select @{name='API'; expression={$role.ResourceDisplayName}},Value,Displayname,@{name='AllowedMemberTypes';expression={($_.AllowedMemberTypes -join ",")}},IsEnabled)
}
Write-output (" >> Current assigned permissions:")
$CurrentAppRoles | ft

Write-Output " >> Retrieving list of App APIs to choose from..."
$RoleAPI = (Get-MgServicePrincipal -Filter "ServicePrincipalType eq 'Application'" -all | ?{$_.AppId -like "000000*"} | sort  DisplayName  | Out-GridView -Title "Choose API" -OutputMode Single)
if($RoleAPI.length -eq $null){
    write-output "  >> Emtpy result, displaying all Apps to choose from..."
    $RoleAPI = (Get-MgServicePrincipal -Filter "ServicePrincipalType eq 'Application'" -all | sort  DisplayName  | Out-GridView -Title "Choose API" -OutputMode Single)
}
if($RoleAPI.length -eq $null){
    break
}

# Get id of enterprise app service principal
$AppPrincipal = (Get-MgServicePrincipal -Filter "displayName eq '$($ServicePrincipal.DisplayName)'")

# Additional Graph role IDs to add
$GraphPrincipal = Get-MgServicePrincipal -Filter "displayName eq '$($RoleAPI)'"
$GraphPrincipal = $RoleAPI

$Roles = ($GraphPrincipal.AppRoles | select Id,Value,Displayname,Description,AllowedMemberTypes,IsEnabled,AdditionalProperties,Origin | Out-GridView -OutputMode Multiple).Value
$oAppRoles = $GraphPrincipal.AppRoles | Where-Object {($_.Value -in $Roles) -and ($_.AllowedMemberTypes -contains "Application")}

Write-Output " >> Assiging API permissions to Service Principal..."
#Add roles to AppPrincipal
foreach($AppRole in $oAppRoles)
{
  $oAppRoleAssignment = @{
    "PrincipalId" = $AppPrincipal.Id
    "ResourceId" = $GraphPrincipal.Id
    "AppRoleId" = $AppRole.Id
  }
  
  if($AppRole.Id -notin (Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $oAppRoleAssignment.PrincipalId).AppRoleId){
    New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $oAppRoleAssignment.PrincipalId -BodyParameter $oAppRoleAssignment -Verbose
  } else {
    echo "$($AppRole.Value) already exists in $($ServicePrincipal)"
  }
}

Write-Output " >> Done!"

<# --== Errata ==--

Prerequisites needed before launching:
- Powershell 5.1 or better
- Graph API module installed (you need to do this in an elevated powershell window): > install-module Microsoft.Graph
- Permissions (or an elevated role) as listed in the header.

Restrictions
- None

To do in later versions:
- Add a removal step: https://learn.microsoft.com/en-us/powershell/module/microsoft.graph.applications/remove-mgserviceprincipalapproleassignment?view=graph-powershell-1.0

Changelog:
- 0.1 Initial version. Mar 30, 2023.
- 0.2 bugfixes and simplify script. May 17, 2024
- 0.2.1 Added documentation Oct 29, 2024
- 0.3 Added picker for service principal and API app 2025-04-17
#>
