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

$TenantId = read-host "Enter Tenant ID"
$justification = read-host "Enter justification"

Connect-MgGraph -NoWelcome -TenantId $TenantId  -Scopes "RoleManagement.Read.All","RoleAssignmentSchedule.ReadWrite.Directory","RoleManagement.ReadWrite.Directory"

# Get the current user context
$context = Get-MgContext
$currentUser = (Get-MgUser -UserId $context.Account).Id

# Get all policy mappings for further rule querying (eg max duration)
[array]$AllRolePolicyMappings = Get-MgPolicyRoleManagementPolicyAssignment -Filter "scopeId eq '/' and scopeType eq 'Directory'"

#Get all admin units
[array]$adminUnits = Get-MgDirectoryAdministrativeUnit | select Id,DisplayName,@{Name="DirectoryScopeId";Expression={"/administrativUnits/$($_.Id)"}}

# Get all available roles assigned to you
[array]$myRoles = Get-MgRoleManagementDirectoryRoleEligibilitySchedule -ExpandProperty RoleDefinition -All -Filter "principalId eq '$currentUser'"

# Get only the role display names and role ids for selection
[array]$availableRoles = $myRoles | Select-Object @{Name="RoleDisplayName";Expression={$_.RoleDefinition.DisplayName}}, @{Name='ScopeDisplayName'; Expression={
    if ($_.DirectoryScopeId -like '*/administrativeUnits/*') {
        $id = ($_.DirectoryScopeId -split '/')[2]
        ($adminUnits | Where-Object { $_.Id -eq $id }).DisplayName 
    } else {
        '/'
    }
}}, RoleDefinitionId

# Display roles in a grid view and prompt the user
[array]$selectedRole = $availableRoles | Out-GridView -Title "Select Role to Activate" -PassThru

# loop through selected roles
if ($selectedRole.count -gt 0) {    
    foreach($role in $selectedRole){
        # Get the max duration for this role
        $policyId = ($AllRolePolicyMappings | ?{$_.RoleDefinitionId -in $role.RoleDefinitionId}).PolicyId
        $ruleId = "Expiration_EndUser_Assignment"
        $Expiry = (Get-MgPolicyRoleManagementPolicyRule -UnifiedRoleManagementPolicyId $policyId -UnifiedRoleManagementPolicyRuleId $ruleId).AdditionalProperties.maximumDuration
        # Get if ticket required
        $ruleId = "Enablement_EndUser_Assignment"
        $Require = (Get-MgPolicyRoleManagementPolicyRule -UnifiedRoleManagementPolicyId $policyId -UnifiedRoleManagementPolicyRuleId $ruleId).AdditionalProperties.enabledRules
        
        Write-Host ("[$($role.RoleDisplayName)]: Activating for $Expiry") -ForegroundColor Cyan

        # Setup parameters for activation
        $params = @{
            Action             = "selfActivate"
            PrincipalId       = $currentUser
            RoleDefinitionId  = $role.RoleDefinitionId
            DirectoryScopeId  = $myRoles[0].DirectoryScopeId
            Justification     = $justification
            ScheduleInfo = @{
                StartDateTime = Get-Date
                Expiration = @{
                    Type     = "AfterDuration"
                    Duration = $Expiry #"PT8H"  #duration for role activation
                }
            }
        }
        If("Ticketing" -in $Require) {
            #get the ticket info
            $ticket = read-host "Enter Ticket number (required)"
            #add the Ticket info
            $params["TicketInfo"] = @{
                TicketNumber = $ticket
                TicketSystem = "N/A"
            }
        }

        # Activate the role
        New-MgRoleManagementDirectoryRoleAssignmentScheduleRequest -BodyParameter $params
        Write-Host "[$($role.RoleDisplayName)]: Role has been scheduled." -ForegroundColor Cyan
        sleep 10
    }
} else {
    Write-Output "No role selected or found."
}
