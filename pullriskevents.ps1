#************************************************ 
# PullSecurityEventReports.ps1 
# Version 0.9 
# Date: 14-11-2019
# Modified by: Fredrik Palmqvist 
# Description: This script will search an Azure AD tenant which has Azure AD Premium and pull the  
# Security related reports using Azure Micorsoft GraphApi. 
# At least one user must be assigned an AAD Premium license for this to work. 
# Results are placed into CSV files for each report/tentant type for review (splunk onboarding)
#************************************************ 
cls 
 
# This script will require the Web Application and permissions setup in Azure Active Directory 
$ClientID       = "-Client ID-"             # Should be a ~35 character string insert  
$ClientSecret   = "-ClientSecret-"
$loginURL       = "https://login.windows.net" 
$tenantdomain   = "-Client Tentant Name"            # For example, contoso.onmicrosoft.com 
 
$tenantname = $tenantdomain.Split('.')[0]
$AuditOutput = $Pwd.Path + "\" + (($tenantname.Split('.')[0]) + "_AuditReport.csv") 
Write-Host "Collecting Azure AD security reports for tenant $tenantdomain`." 
 
function GetReport      ($url, $reportname, $tenantname) { 
$AuditOutputCSV = $Pwd.Path + "\" + (($tenantname.Split('.')[0]) + "_AuditReport.csv") 
# Get an Oauth 2 access token by client id, secret and tenant domain 
$loginURLL = "https://login.microsoft.com" 
$resource = "https://graph.microsoft.com" 
$body       = @{grant_type="client_credentials";resource=$resource;client_id=$ClientID;client_secret=$ClientSecret} 
$oauth      = Invoke-RestMethod -Method Post -Uri $loginURL/$tenantname/oauth2/token?api-version=1.0 -Body $body 
$AuditOutputCSV = $Pwd.Path + "\" + $tenantname + "_$reportname.csv" 
Write-Host "Collecting Azure AD security report "  $reportname "..." 
if ($oauth.access_token -ne $null) { 
    $headerParams = @{'Authorization'="$($oauth.token_type) $($oauth.access_token)"} 

    $url = "https://graph.microsoft.com/beta/identityRiskEvents?$filter=riskLevel eq 'high'" #Collect filtering 


    $myReport = (Invoke-WebRequest -UseBasicParsing -Headers $headerParams -Uri $url) 
    $ConvertedReport = ConvertFrom-Json -InputObject $myReport.Content  
    $XMLReportValues = $ConvertedReport.value 
    if ($ConvertedReport.value.count -le 100) 
        { 
            $nextURL = $ConvertedReport."@odata.nextLink" 
            if (($ConvertedReport.value.count -ne 0) -and ($nextURL -ne $null)){ 
            Do { #Collect any additional results into array 
                     $nextURL = $ConvertedReport."@odata.nextLink" 
                     $Report =  Invoke-WebRequest -UseBasicParsing -Headers $headerParams -Uri $nextURL 
                     $ConvertedReport = ConvertFrom-Json -InputObject $Report.Content 
                     $XMLReportValues += $ConvertedReport 
                } 
                While ($NextResults."@odata.nextLink" -ne $null) 
         } 
 
    #Place into a CSV 
    $AuditOutputCSV = $Pwd.Path + "\" + $tenantname + "_$reportname.csv" 
    $XMLReportValues | select * | Export-csv $AuditOutputCSV -NoTypeInformation -Force -append 
    Write-host "Security report for Risk Events can be found at" $AuditOutputCSV "." 
       }     
 
       if ($ConvertedReport.value.count -eq 0) 
        { 
        $AuditOutputCSV = $Pwd.Path + "\" + $tenantname + "_$reportname.txt" 
        Get-Date |  Out-File -FilePath $AuditOutputCSV  
        "No Data Returned. This typically means either the tenant does not have Azure AD Premium licensing or that the report query succeeded however there were no entries in the report. " |  Out-File -FilePath $AuditOutputCSV -Append 
        } 
       
    } 
 
} 
 
 
GetReport $url "identityRiskEvents" $tenantdomain
