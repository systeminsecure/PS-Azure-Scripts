$TenantId = read-host "Enter Tenant ID"
$justification = read-host "Enter justification"

Connect-MgGraph -NoWelcome -TenantId $TenantId 

# Get the current user context
$context = Get-MgContext
$currentUser = (Get-MgUser -UserId $context.Account).Id

# Get all available roles assigned to you
$myRoles = Get-MgRoleManagementDirectoryRoleEligibilitySchedule -ExpandProperty RoleDefinition -All -Filter "principalId eq '$currentUser'"

# Get only the role display names and role ids for selection
$availableRoles = $myRoles | Select-Object @{Name="RoleDisplayName";Expression={$_.RoleDefinition.DisplayName}}, RoleDefinitionId

# Display roles in a grid view and prompt the user
$selectedRole = $availableRoles | Out-GridView -Title "Select Role to Activate" -PassThru

if ($selectedRole) {
    
    foreach($role in $selectedRole){
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
                    Duration = "PT8H"  #duration for role activation
                }
            }
        }

        # Activate the role
        New-MgRoleManagementDirectoryRoleAssignmentScheduleRequest -BodyParameter $params
        Write-Output "$($role.RoleDisplayName) role has been scheduled."
        sleep 5
    }
} else {
    Write-Error "No role selected or found."
}
