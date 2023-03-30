<# Azure Risky Network Security Groups v0.1 SystemInsecure
--== Jan 27, 2023 ==--

This script lists out all Azure NSGs in a subscription and evaluates them for the following conditions:

- Rules that have a destination IP address and port set to "Any" (marked yellow)
- Rules that have a source and destination IP address set to "Any" (marked red)

You must have the Az module installed first: Install-Module Az

See Errata section at bottom for prerequisites, restrictions and the changelog.

#>

$global:Subscription = (Get-AzSubscription | out-gridview -title "Select a subscription" -OutputMode Single)
if ($global:Subscription -eq $null) { ErrorHandler -handle "Subscription"; break }
set-azcontext -Subscription $Subscription.Id

$objects = @()
$objects = Get-AzNetworkSecurityGroup

$DomainName = (Invoke-AzRestMethod `
                    -Method get `
                    -Uri https://graph.microsoft.com/v1.0/domains `
                        | Select-Object -ExpandProperty Content `
                        | Convertfrom-json `
                        | Select-Object -ExpandProperty value `
                        | where-object -Property  isDefault -eq $true `
                        | Select-Object -ExpandProperty id)

foreach ($rule in $objects.SecurityRules ){

    if ($rule.Direction -like "*nbound" -and $rule.Access -like "*llow"){
        $color= "Gray"

        if ($rule.DestinationPortRange -eq "*" -and $rule.DestinationAddressPrefix -eq "*"){
            $color = "Yellow"
            }
        if ($rule.SourceAddressPrefix -eq "*" -and $rule.DestinationAddressPrefix -eq "*"){
            $color = "Red"
            }

        if ($rule.SourceApplicationSecurityGroups.count -eq 0){
            $source=$rule.SourceAddressPrefix
            } else {
            $source=($rule.SourceApplicationSecurityGroups[0].Id -split("/"))[-1]
            }

        if ($rule.DestinationApplicationSecurityGroups.count -eq 0){
            $dest=$rule.DestinationAddressPrefix
            } else {
            $dest=($rule.DestinationApplicationSecurityGroups[0].Id -split("/"))[-1]
            }

    if ($color -ne "Gray"){
            Write-host("$($rule.Id.Split("/")[8]) :: $($rule.Id.Split("/")[-1]) :: $($rule.Priority)") -ForegroundColor Cyan
            Write-host("Priority $($rule.Priority)") -ForegroundColor $color
            Write-host("Source IP $($source)") -ForegroundColor $color
            Write-host("Dest IP $($dest)") -ForegroundColor $color
            Write-host("Dest Ports $($rule.DestinationPortRange)") -ForegroundColor $color
            Write-host("Direction $($rule.Direction)") -ForegroundColor $color
            $object= $objects | where {$_.Etag.split("""")[-2] -eq ($rule.Etag.split("""")[-2])}
                if ($object.NetworkInterfaces.count -ne 0){
                    Write-host(">> Number of connected NICs: $($object.NetworkInterfaces.count)") -ForegroundColor $color
                }
                if ($object.Subnets.count -ne 0){
                    Write-host(">> Number of connected Subnets: $($object.Subnets.count)") -ForegroundColor $color
                }
                if ($object.Subnets.count -eq 0 -and $object.NetworkInterfaces.count -eq 0){
                    Write-host(">> NOT USED") -ForegroundColor $color
                }
            Write-host("https://portal.azure.com/#@$($DomainName)/resource$(($rule.Id -split("securityRules"))[0])") -ForegroundColor White
            Write-host(" ")
            }
    }

}

<# --== Errata ==--

Prerequisites needed before launching:
- Powershell 5.1 or better
- Az module installed (you need to do this in an elevated powershell window): > install-module Az
- Permissions (or an elevated role) to read the Network Security Group rules (recommend Contributor access to the Subscription or all Resource Groups).

Restrictions
- None

To do in later versions:
- Nothing planned

Changelog:
- 0.1 Initial version. Jan 27, 2023.
#>
