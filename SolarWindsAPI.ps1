﻿
#Global Parameters
$global:APIRootPath = 'api2/perfstack'

<#
  .SYNOPSIS
  Changes the Certificate Trust policy to Trust All Certificates
  .DESCRIPTION
  This is a well known function that allows you connect to any URL while ignoring any certificate trust.
  .EXAMPLE
  Enable-TrustAllCertificates
#>

function Enable-TrustAllCertificates {
    [CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='Low')]
    param()
    try{
        Write-Verbose "Adding TrustAllCertsPolicy type." 
        Add-Type -TypeDefinition  @"
        using System.Net;
        using System.Security.Cryptography.X509Certificates;
        public class TrustAllCertsPolicy : ICertificatePolicy
        {
             public bool CheckValidationResult(
             ServicePoint srvPoint, X509Certificate certificate,
             WebRequest request, int certificateProblem)
             {
                 return true;
            }
        }
"@
        Write-Verbose "TrustAllCertsPolicy type added."
      }
    catch{
        Write-Error $_
    }
    If ($pscmdlet.ShouldProcess([System.Net.ServicePointManager]::CertificatePolicy)){
        Return [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
    }
}

<#
  .SYNOPSIS
  Creates a Basic Authentication Credential
  .DESCRIPTION
  Builds a basic authentication crendential to use against the solarwinds API. This is required to connect to SolarWinds.
  You must have basic authentication enable on your IIS website for all servers that host the solarwinds website. This is not enabled by default.
  .PARAMETER Username
  Your username in clear text
  .PARAMETER Password
  Your password in clear text
  .EXAMPLE
  Get-BasicAuthCreds -Username 'domain\username' -Password 'P@ssw0rd'
#>

Function New-BasicAuthCreds {
    param(
        [Parameter(Mandatory=$True,
        ValueFromPipeline=$True,
        ValueFromPipelineByPropertyName=$True)]
        [ValidateNotNull()]
        [string]$Username,

        [Parameter(Mandatory=$True,
        ValueFromPipeline=$True,
        ValueFromPipelineByPropertyName=$True)]
        [ValidateNotNull()]
        [string]$Password
    )

    $AuthString = "{0}:{1}" -f $Username,$Password
    $AuthBytes  = [System.Text.Encoding]::Ascii.GetBytes($AuthString)
    return [Convert]::ToBase64String($AuthBytes)
}

<#
  .SYNOPSIS
  Creates a new SolarWinds rest API session
  .DESCRIPTION
  Uses the invoke-restmethod to create an API session the solarwinds APIv2 interface
  .PARAMETER ServerName
  The solarwinds FQDN servername. 
  .PARAMETER Credential
  Accepts a single Base64Encoded Credential. Use the New-BasicAuthCreds Function to generate a credential
  .PARAMETER ServerPort
  Only required if your solarwinds website is not running on the default port of 443
  .EXAMPLE
  New-SWAPISession -ServerName solarwinds.test.com -Credential $Cred
  .EXAMPLE
  New-SWAPISession -ServerName 'solarwinds.test.com' -Credential $Cred -ServerPort '6751'
  .NOTES
  Assumes your solarwinds website is using SSL and running on the default port of 443. 
  If you are not running SSL on your solarwinds website you should fix this as credentials are passed in base64encoded clear text
#>

Function New-SWSession {
    [CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='Low')]
    param(
        [Parameter(Mandatory=$True,
        ValueFromPipeline=$True,
        ValueFromPipelineByPropertyName=$True)]
        [ValidateNotNull()]
        [Alias('Server')]
        [Alias('SolarWindsServer')]
        [string]$ServerName,

        [Parameter(Mandatory=$True,
        ValueFromPipeline=$True,
        ValueFromPipelineByPropertyName=$True)]
        [ValidateNotNull()]
        [Alias('Creds')]
        [Alias('Cred')]
        [string]$Credential,

        [Alias('Port')]
        [string]$ServerPort = '443'
    )

    begin {
        Write-Verbose 'Formatting ServerName to Base solarwinds address for establishing a session'
        $URI = "https://$($ServerName):$($ServerPort)/orion"
    }

    process {
        try{
            Write-Verbose "Attempting Connection to $URI"
            If ($pscmdlet.ShouldProcess($URI)){

                $Session = Invoke-WebRequest -Method Get -Uri $URI -ContentType 'application/json' -Headers @{"Authorization"="Basic $Credential"} -SessionVariable SWSession

                Write-Verbose $Session.StatusCode
                Write-Verbose $Session.StatusDescription
                Write-Verbose $Session.Headers.'Set-Cookie'

                #Create a cookie in the Session Variable with the current SessionID
                $Cookie = New-Object System.Net.Cookie
                $Cookie.Name = "Id"
                $Cookie.Name = "/"
                #Best way I could figure out how to get the current SessionID from the Session; #Regex skills needed :)
                $Cookie.Name = $Session.Headers.'Set-Cookie'.Split(';')[0].Replace('ASP.NET_SessionId=','')
                $Cookie.Domain = $ServerName

                Write-Verbose $Cookie.Name
                Write-Verbose $Cookie.Domain

                # Add cookie to your websession
                $SWSession.Cookies.Add($Cookie);
            }

            #Create a new PSObject to store session data
            $Object = New-Object PSObject -Property @{
                WebSession = $SWSession
                ServerName = $ServerName
                ServerPort = $ServerPort
            }
        }
        catch{

            Write-Error $_

        }

        return $Object
    }
}

<#
  .SYNOPSIS
  Gets a list of entities from an API endpoint Path
  .DESCRIPTION
  This is a univeral function that returns a list of objects from the entities API endpoint. 
  .PARAMETER ServerName
  The solarwinds FQDN servername. 
  .PARAMETER WebSession
  An existing Microsoft.PowerShell.Commands.WebRequestSession. Use the New-SolarWindsSession to generate a web session
  .PARAMETER Endpoint
  Specify the API Endpoint Path. (entities/states/, entities/types, entities, etc...)
  .PARAMETER ServerPort
  Only required if your solarwinds website is not running on the default port of 443
  .PARAMETER Offset
  The offset parameter controls the starting point within the collection of resource results. 
  For example, if you have a collection of 15 items to be retrieved from a resource and you specify Length=5, 
  you can retrieve the entire set of results in 3 successive requests by varying the offset value: offset=0, offset=5, and offset=10. 
  Note that the first item in the collection is retrieved by setting a zero offset..
  .PARAMETER Length
  The Length parameter controls the maximum number of items that may be returned for a single request. 
  This parameter can be thought of as the page size. If no length is specified, the system defaults to a length of 0 or all records.
  .PARAMETER OrderBy
  The orderBy parameter can be used to order results based on a specific attribute
  .PARAMETER Sort
  The Sort parameter can be used to sort results based on a specific attribute
  .PARAMETER DisplayName
  The displayName parameter can be used to filter results basde on the displayname attribute. Wildcards can be represented by a % sign.
  .PARAMETER status
  The Status parameter can be used to sort results based on the status of an object
  .PARAMETER type
  The Type parameter can be used to sort results based on the type of an object. This useful for only returning nodes for example. 
  ?length=20&offset=5&sort=description&type=Orion.Nodes
  Returns a subset of objects based on an attribute. Expects a string in the format of 'attribute=value'. 
  Specify multiple attributes seperated by the & symbol 'attribute=value&attribute2=value'

  To see current attributes run Get-Nodes -ShowAttributes
  .PARAMETER ShowAttributes
  Shows an example of the attributes you can filter on. 
  .EXAMPLE
  Get All Nodes
  Get-SWObjects -ServerName solarwinds.test.com -WebSession $WebSession -Path 'entities/'
  .EXAMPE
  Get All Metric Types
  Get-SWObjects -ServerName solarwinds.test.com -WebSession $WebSession -Path 'metrics/'
   .EXAMPE
  Get All Metric Types by Group
  Get-SWObjects -ServerName solarwinds.test.com -WebSession $WebSession -Path 'entities/types/'
    .EXAMPE
  Get All States
  Get-SWObjects -ServerName solarwinds.test.com -WebSession $WebSession -Path 'entities/states/'
  .EXAMPLE
  Get Top 5 nodes
  Get-SWObjects -ServerName solarwinds.test.com -WebSession $WebSession -Path 'entities/' -Limit 5
  .EXAMPLE
  Using the Filter Paramater

  Get All Nodes that are down
  Get-SWObjects -ServerName solarwinds.test.com -WebSession $WebSession -Filter -Path 'entities/' 'status=2'

  Get a single node based on displayname
  Get-SWObjects -ServerName solarwinds.test.com -WebSession $WebSession -Filter -Path 'entities/' 'displayName=test.internal.net'

  Get nodes based on a Like Operator using %. Below will return all nodes with srv in the displayName
  Get-SWObjects -ServerName solarwinds.test.com -WebSession $WebSession -Path 'entities/' -Filter 'displayName=%srv%'

  Get nodes based on multiple filters. Below will return all nodes with srv in the displayName and have windows in the description
  Get-SWObjects -ServerName solarwinds.test.com -WebSession $WebSession -Path 'entities/' -Filter 'displayName=%srv%&description=%windows%'


#>

Function Get-SWObjects{
    [CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='Low',DefaultParametersetName='ParamDefault')]
    param(
        [Parameter(Mandatory=$false,
        ValueFromPipeline=$True,
        ValueFromPipelineByPropertyName=$True)]
        [ValidateNotNull()]
        [Alias('Server')]
        [Alias('SolarWindsServer')]
        [string]$ServerName,
        
        [Parameter(Mandatory=$false,
        ValueFromPipeline=$True,
        ValueFromPipelineByPropertyName=$True)]
        [Alias('Port')]
        [string]$ServerPort = '443',

        [Parameter(Mandatory=$false,
        ValueFromPipeline=$True,
        ValueFromPipelineByPropertyName=$True)]
        [ValidateNotNull()]
        [Microsoft.PowerShell.Commands.WebRequestSession]$WebSession,

        [Parameter(Mandatory=$True,
        ValueFromPipelineByPropertyName=$True)]
        [ValidateNotNull()]
        [string]$EndPoint,

        [Parameter(ParameterSetName = 'ParamShowAtrribs')]
        [switch]$ShowAttributes = $false,

        [int]$Limit = 0,

        [Parameter(ParameterSetName = 'ParamFilterAtrribs')]
        [string]$Filter
    )

    begin {
       
        Write-Verbose "Parameter Set: $($PSCmdlet.ParameterSetName)"
    }

    process {
        
        Write-Verbose $Temp.Websession.headers

        #Cleanup Path Variable
        $EndPoint = $EndPoint.Replace('//','/')

        Write-Verbose 'Formatting ServerName to Base solarwinds address for establishing a session'
        
        $URI = "$($ServerName):$($ServerPort)/$global:APIRootPath/$EndPoint/?length=$Limit&offset=0"
        
        If($Filter){
            Write-Verbose 'Filter Parameter Was Specified, Formatting URI'
            $URI = "$($ServerName):$($ServerPort)/$global:APIRootPath/$EndPoint/?length=$Limit&offset=0$Filter"
        }

        If($ShowAttributes){
            Write-Verbose 'ShowAttributes Parameter Was Specified, Formatting URI'
            $URI = "$($ServerName):$($ServerPort)/$global:APIRootPath/$EndPoint/?length=$Limit&offset=0"
        }

        #Cleanup URI  Variable
        $URI  = "https://$($URI.Replace('//','/'))"
        
        try{
            Write-Verbose "Attempting Connection to $URI"
            If ($pscmdlet.ShouldProcess($URI)){

                $Request = Invoke-RestMethod -Method Get -Uri $URI -ContentType 'application/json' -WebSession $WebSession
            }

        }
        catch{

            Write-Error $_

        }

    }
    End{
        #Only Return Filterable Attributes if specified
        If($ShowAttributes){
            $Request = $Request.data
        }

        return $Request
    }
}

<#
  .SYNOPSIS
  Gets a list of Nodes from the SolarWinds API
  .DESCRIPTION
  Returns a list of nodes from the /api2/perfstack/entities API endpoint uses the filter type=Orion.Nodes to only display nodes
  .PARAMETER ServerName
  The solarwinds FQDN servername. 
  .PARAMETER WebSession
  An existing Microsoft.PowerShell.Commands.WebRequestSession. Use the New-SolarWindsSession to generate a web session
  .PARAMETER ServerPort
  Only required if your solarwinds website is not running on the default port of 443
  .PARAMETER Limit
  Returns a subset of objects from the request. Expects an integer ranging from 0 to unkown number. Default value is 0 which returns all nodes.
  You cannot specify the Filter or ShowAttributes parameters with this parameter.
  .PARAMETER Filter
  Returns a subset of objects based on an attribute. Expects a string in the format of 'attribute=value'. 
  Specify multiple attributes seperated by the & symbol 'attribute=value&attribute2=value'
  To see current attributes run Get-Nodes -ShowAttributes
  You cannot specify the Limit or ShowAttributes parameters with this parameter. 
  .PARAMETER ShowAttributes
  Shows an example of the attributes you can filter on. You cannot specify the Limit or Filter parameters with this parameter. 
  .PARAMETER Endpoint
  Should only be used for development purposes. Specifies the nodes API endpoint, default is entities/
  .EXAMPLE
  Get All Nodes
  Get-SWNodes -ServerName solarwinds.test.com -WebSession $WebSession
  .EXAMPLE
  Get Top 5 nodes
  Get-SWNodes -ServerName solarwinds.test.com -WebSession $WebSession -Limit 5
  .EXAMPLE
  Using the Filter Paramater

  Get All Nodes that are down
  Get-SWNodes -ServerName solarwinds.test.com -WebSession $WebSession -Filter 'status=2'

  Get a single node based on displayname
  Get-SWNodes -ServerName solarwinds.test.com -WebSession $WebSession -Filter 'displayName=test.internal.net'

  Get nodes based on a Like Operator using %. Below will return all nodes with srv in the displayName
  Get-SWNodes -ServerName solarwinds.test.com -WebSession $WebSession -Filter 'displayName=%srv%'

  Get nodes based on multiple filters. Below will return all nodes with srv in the displayName and have windows in the description
  Get-SWNodes -ServerName solarwinds.test.com -WebSession $WebSession -Filter 'displayName=%srv%&description=%windows%'

#>

Function Get-SWNodes{
    [CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='Low',DefaultParametersetName='ParamDefault')]
    param(
        [Parameter(Mandatory=$false,
        ValueFromPipeline=$True,
        ValueFromPipelineByPropertyName=$True)]
        [ValidateNotNull()]
        [Alias('Server')]
        [Alias('SolarWindsServer')]
        [string]$ServerName,
        
        [Parameter(Mandatory=$false,
        ValueFromPipeline=$True,
        ValueFromPipelineByPropertyName=$True)]
        [Alias('Port')]
        [string]$ServerPort = '443',

        [Parameter(Mandatory=$false,
        ValueFromPipeline=$True,
        ValueFromPipelineByPropertyName=$True)]
        [ValidateNotNull()]
        [Microsoft.PowerShell.Commands.WebRequestSession]$WebSession,

        [Parameter(ParameterSetName = 'ParamShowAtrribs')]
        [switch]$ShowAttributes = $false,

        [Parameter(ParameterSetName = 'ParamLimit')]
        [int]$Limit = 0,

        [Parameter(ParameterSetName = 'ParamFilterAtrribs')]
        [string]$Filter,

        [Alias('Path')]
        [string]$Endpoint = 'entities/'

    )

    begin {

    }

    process {

        #Cleanup Path Variable
        $EndPoint = ($EndPoint + '/').Replace('//','/')

        Write-Verbose 'Formatting ServerName to Base solarwinds address for establishing a session'
        
        $URI = "$($ServerName):$($ServerPort)/$global:APIRootPath/$EndPoint/?length=$Limit&offset=0&type=Orion.Nodes"
        
        If($Filter){
            Write-Verbose 'Filter Parameter Was Specified, Formatting URI'
            $URI = "$($ServerName):$($ServerPort)/$global:APIRootPath/$EndPoint/?$Filter&offset=0&type=Orion.Nodes"
        }

        If($ShowAttributes){
            Write-Verbose 'ShowAttributes Parameter Was Specified, Formatting URI'
            $URI = "$($ServerName):$($ServerPort)/$global:APIRootPath/$EndPoint/?length=1&offset=0&type=Orion.Nodes"
        }

        #Cleanup URI  Variable
        $URI  = "https://$($URI.Replace('//','/'))"

        try{
            Write-Verbose "Attempting Connection to $URI"
            If ($pscmdlet.ShouldProcess($URI)){

                $Request = Invoke-RestMethod -Method Get -Uri $URI -ContentType 'application/json' -WebSession $WebSession
            }

        }
        catch{

            Write-Error $_

        }

    }
    End{
        #Only Return Filterable Attributes if specified
        If($ShowAttributes){
            $Request = $Request.data
        }

        return $Request
    }
}

<#
  .SYNOPSIS
  Gets a list of node related metrics 
  .DESCRIPTION
  Returns a list of all metrics from the current node. 
  .PARAMETER ServerName
  The solarwinds FQDN servername. 
  .PARAMETER WebSession
  An existing Microsoft.PowerShell.Commands.WebRequestSession. Use the New-SolarWindsSession to generate a web session
  .PARAMETER NodeID
  The NodeID of the Node you want to retrieve metrics from. This needs to be in the API format. 0_Orion.Nodes_NodeID where NodeID is the NodeID number (0_Orion.Nodes_2055)
  .PARAMETER ServerPort
  Only required if your solarwinds website is not running on the default port of 443
  .EXAMPLE
  Get-SWNodeMetrics -ServerName solarwinds.f5net.com -WebSession $WebSession -NodeID 0_Orion.Nodes_2055
#>
Function Get-SWNodeMetrics{
    [CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='Low',DefaultParametersetName='ParamDefault')]
    param(
        [Parameter(Mandatory=$false,
        ValueFromPipeline=$True,
        ValueFromPipelineByPropertyName=$True)]
        [ValidateNotNull()]
        [Alias('Server')]
        [Alias('SolarWindsServer')]
        [string]$ServerName,
        
        [Parameter(Mandatory=$false,
        ValueFromPipeline=$True,
        ValueFromPipelineByPropertyName=$True)]
        [Alias('Port')]
        [string]$ServerPort = '443',

        [Parameter(Mandatory=$false,
        ValueFromPipeline=$True,
        ValueFromPipelineByPropertyName=$True)]
        [ValidateNotNull()]
        [Microsoft.PowerShell.Commands.WebRequestSession]$WebSession,

        [Parameter(Mandatory=$True)]
        [ValidateNotNull()]
        [string]$NodeID,

        [Alias('Path')]
        [string]$Endpoint = 'metrics/'

    )

    begin {

    }

    process {
        
        #Cleanup Path Variable
        $EndPoint = ($EndPoint + '/').Replace('//','/')

        Write-Verbose 'Formatting ServerName to Base solarwinds address for establishing a session'
        
        $URI = "$($ServerName):$($ServerPort)/$global:APIRootPath/entities/$NodeID/$EndPoint"

        #Cleanup URI  Variable
        $URI  = "https://$($URI.Replace('//','/'))"

        try{
            Write-Verbose "Attempting Connection to $URI"
            If ($pscmdlet.ShouldProcess($URI)){

                $Request = Invoke-RestMethod -Method Get -Uri $URI -ContentType 'application/json' -WebSession $WebSession
            }

        }
        catch{

            Write-Error $_

        }

    }
    End{

        return $Request
    }

}

<#
  .SYNOPSIS
  Gets a statistics from a metric
  .DESCRIPTION
  Returns a list of all statisics from a metric object
  .PARAMETER ServerName
  The solarwinds FQDN servername. 
  .PARAMETER WebSession
  An existing Microsoft.PowerShell.Commands.WebRequestSession. Use the New-SolarWindsSession to generate a web session
  .PARAMETER MetricID
  The NodeID of the Node you want to retrieve metrics from. This needs to be in the API format. 0_Orion.Nodes_NodeID where NodeID is the NodeID number (0_Orion.Nodes_2055)
  .PARAMETER Latest
  Gets the last available measurement
  .PARAMETER StartTime
  Specify series of measurements to retrive based on the timeframe. Must be a date time object. (For Future Use Not Yet Implmented)
.PARAMETER EndTime
  Specify series of measurements to retrive based on the timeframe. Must be a date time object. (For Future Use Not Yet Implmented)
  .PARAMETER Endpoint
  Specify the API Endpoint Path. (default is /metrics)
  .PARAMETER ServerPort
  Only required if your solarwinds website is not running on the default port of 443
  .EXAMPLE
  Get-SWMeasurement -ServerName solarwinds.f5net.com -WebSession $WebSession -MetricID 0_Orion.Nodes_3341-Orion.CPULoad.AvgLoad
  .EXAMPLE
  Get-SWMeasurement -ServerName solarwinds.f5net.com -WebSession $WebSession -MetricID 0_Orion.Nodes_3341-Orion.CPULoad.AvgLoad -Latest
    .EXAMPLE
  Get-SWMeasurement -ServerName solarwinds.f5net.com -WebSession $WebSession -MetricID 0_Orion.Nodes_3341-Orion.CPULoad.AvgLoad -TimeFrame
#>
Function Get-SWMeasurement{
    [CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='Low',DefaultParametersetName='ParamDefault')]
    param(
        [Parameter(Mandatory=$false,
        ValueFromPipeline=$True,
        ValueFromPipelineByPropertyName=$True)]
        [ValidateNotNull()]
        [Alias('Server')]
        [Alias('SolarWindsServer')]
        [string]$ServerName,
        
        [Parameter(Mandatory=$false,
        ValueFromPipeline=$True,
        ValueFromPipelineByPropertyName=$True)]
        [Alias('Port')]
        [string]$ServerPort = '443',

        [Parameter(Mandatory=$false,
        ValueFromPipeline=$True,
        ValueFromPipelineByPropertyName=$True)]
        [ValidateNotNull()]
        [Microsoft.PowerShell.Commands.WebRequestSession]$WebSession,

        [Parameter(Mandatory=$True)]
        [ValidateNotNull()]
        [Alias('id')]
        [string]$MetricID,

        [switch]$Latest,

        [Alias('Path')]
        [string]$Endpoint = 'metrics/'
    )

    begin {

    }

    process {

        #Get Current Date Time in UTC
        $EndTime = (get-date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        $StartTime = (get-date).AddHours(-1).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

        #Cleanup Path Variable
        $EndPoint = ($EndPoint + '/').Replace('//','/')

        Write-Verbose 'Formatting ServerName to Base solarwinds address for establishing a session'
        
        $URI = "$($ServerName):$($ServerPort)/$global:APIRootPath/$EndPoint/$MetricID/"

        #Cleanup URI  Variable
        $URI  = "https://$($URI.Replace('//','/'))/"

        try{
            Write-Verbose "Attempting Connection to $URI"
            If ($pscmdlet.ShouldProcess($URI)){

                $Request = Invoke-RestMethod -Method Get -Uri $URI -ContentType 'application/json' -WebSession $WebSession
            }

        }
        catch{

            Write-Error $_

        }

    }
    End{
        If($Latest){
            $Request = $Request[0]
        }

        return $Request
    }

}

