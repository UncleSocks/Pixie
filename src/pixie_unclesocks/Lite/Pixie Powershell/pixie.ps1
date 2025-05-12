
param([string]$ApiKey, 
      [string]$FilePath, 
      [string]$OutputPath
)


Function AbuseIpLookup {

    $processedIpArray = @()
    $fileContent = Get-Content -Path $FilePath
    
    $headers = @{
        'Key' = $ApiKey
        'Accept' = 'application/json'
    }    
    
    foreach ($line in $fileContent) {

        $body = @{
            'ipAddress' = $line
            'maxAgeInDays' = '90'
        }

        $Params = @{
            Uri = 'https://api.abuseipdb.com/api/v2/check'
            Method = 'GET'
            Headers = $headers
            Body = $body
        }

        $lookup = Invoke-RestMethod @Params
        #$lookupParsed = $lookup | ConvertTo-Json #Convert JSON to a more human-readable format.
        #Write-Output $lookupParsed #Print human-readable JSON response for testing.

        $ipAddress = $lookup.data.ipAddress
        $isPublic = $lookup.data.isPublic

        if ($isPublic -eq $true) {
          
          try {
            $countryCode = $lookup.data.countryCode
          } catch {
            $countryCode = 'N/A'
          }   
          
          try {
            $isp = $lookup.data.isp
          } catch {
            $isp = 'N/A'
          }

          try {
            $domain = $lookup.data.domain
          } catch {
            $domain = 'N/A'
          }

          $abuseConfidenceScore = $lookup.data.abuseConfidenceScore
          $totalReports = $lookup.data.totalReports
          $lastReportedAt = $lookup.data.lastReportedAt

        } else {

            $countryCode = 'N/A'
            $isp = 'PRIVATE'
            $abuseConfidenceScore = 'N/A'
            $totalReports = 'N/A'
            $lastReportedAt = 'N/A'
        }
        
        $processedIp = [PSCustomObject]@{
            'IP Address' = $ipAddress
            'Country Code' = $countryCode
            'ISP' = $isp
            'Domain' = $domain
            'Abuse Confidence Score (%)' = $abuseConfidenceScore
            'Total Reports' = $totalReports
            'Last Reported At' = $lastReportedAt
        }

        $processedIpArray += $processedIp

    }

    $processedIpArray | Export-Csv $OutputPath -Encoding UTF8 -NoTypeInformation

}

AbuseIPLookup -ApiKey $ApiKey -FilePath $FilePath -OutputPath $OutputPath