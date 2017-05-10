
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

Function New-SWBasicAuthCreds {
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
  Accepts a single Base64Encoded Credential. Use the New-SWBasicAuthCreds Function to generate a credential
  .PARAMETER ServerPort
  Only required if your solarwinds website is not running on the default port of 443
  .EXAMPLE
  New-SWSession -ServerName solarwinds.test.com -Credential $Cred
  .EXAMPLE
  New-SWSession -ServerName 'solarwinds.test.com' -Credential $Cred -ServerPort '6751'
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
  Gets a list of entities 
  .DESCRIPTION
  Gets a list of entities from the entities API endpoint. Please read the list of valid paramaters for filtering. 
  .PARAMETER ServerName
  The solarwinds FQDN servername. 
  .PARAMETER WebSession
  An existing Microsoft.PowerShell.Commands.WebRequestSession. Use the New-SWSession to generate a web session
  .PARAMETER Endpoint
  Specify the API Endpoint Path. (entities/states/, entities/types, entities, etc...). The default is entities.
  .PARAMETER ServerPort
  Only required if your solarwinds website is not running on the default port of 443
  .PARAMETER Offset
  The offset parameter controls the starting point within the collection of resource results. 
  For example, if you have a collection of 15 items to be retrieved from a resource and you specify Length=5, 
  you can retrieve the entire set of results in 3 successive requests by varying the offset value: offset=0, offset=5, and offset=10. 
  Note that the first item in the collection is retrieved by setting a zero offset. The Default value is 0.
  .PARAMETER Length
  The Length parameter controls the maximum number of items that may be returned for a single request. 
  The Default value is 10. A length value of 0 will return all entities (This will take a while to process). 
  .PARAMETER OrderBy
  The orderBy parameter can be used to order results based on a specific attribute
  .PARAMETER Sort
  The Sort parameter can be used to sort results based on a specific attribute
  .PARAMETER DisplayName
  The displayName parameter can be used to filter results basde on the displayname attribute. Wildcards can be represented by a % sign.
  .PARAMETER status
  The Status parameter can be used to sort results based on the status of an object
  .PARAMETER type
  The Type ot instanceType parameter can be used to sort results based on the type of an object. For example you can specifcy a type of nodes to only return node entities.
  .PARAMETER ShowAttributes
  Shows an example of the attributes you can filter on. This parameter cannot be used with any other filter paramaters. 
  .EXAMPLE
  In the below examples the variable $WebSession was created using the New-SWSession cmdlet
  .EXAMPLE
  Get the first 10 entities
  $WebSession | Get-SWEntities
  .EXAMPLE
  The below examples work with returning a limited number of records using the Length and Offset parameters

  $WebSession | Get the first 50 entities 
  $WebSession | Get-SWEntities -Length 50

  Get the first 50 entities with an offset of 2
  $WebSession | Get-SWEntities -Length 50 -Offset 2
  .EXAMPLE
  The below examples work with returning a entities based on a type.

  Get the first 10 entities that are nodes 
  $WebSession | Get-SWEntities -type Orion.Nodes

  Get all entities that are nodes
  $WebSession | Get-SWEntities -type Orion.Nodes -Length 0

  Get all entities that are Exchange APM Applications
  $WebSession | Get-SWEntities -type Orion.APM.Exchange.Application
  .EXAMPLE
  Get all entities that have a displayname of test.test.local
  $WebSession | Get-SWEntities -DisplayName test.test.local

  Get all entities that have a displayname beginning with test
  $WebSession | Get-SWEntities -DisplayName test%

  .EXAMPLE
  The below examples work with returning a entities based on a status. 

  Get the first 10 entities that are down
  $WebSession | Get-SWEntities -status 2

  .EXAMPLE
  The below examples sort and OrderBy the records returned. 

  Get the first 100 nodes, sort by status
  $WebSession | Get-SWEntities -type Orion.Nodes -sort status

  Get the first 100 nodes, groupby description
  $WebSession | Get-SWEntities -type Orion.Nodes -OrderBy description

#>

Function Get-SWEntities{
    [CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='Low',DefaultParametersetName='ParamDefault')]
    param(
        [Parameter(Mandatory=$true,
        ValueFromPipeline=$True,
        ValueFromPipelineByPropertyName=$True)]
        [ValidateNotNull()]
        [Alias('Server')]
        [Alias('SolarWindsServer')]
        [string]$ServerName,
        
        [Parameter(Mandatory=$true,
        ValueFromPipeline=$True,
        ValueFromPipelineByPropertyName=$True)]
        [ValidateNotNull()]
        [Microsoft.PowerShell.Commands.WebRequestSession]$WebSession,

        [Parameter(ValueFromPipeline=$True,
        ValueFromPipelineByPropertyName=$True)]
        [Alias('Port')]
        [int]$ServerPort = '443',

        [Parameter(ValueFromPipelineByPropertyName=$True,ParameterSetName = 'ParamQuery')]
        [ValidateNotNull()]
        [string]$EndPoint = 'entities',

        [Parameter(ValueFromPipelineByPropertyName=$True,ParameterSetName = 'ParamQuery')]
        [int]$Offset = 0,

        [Parameter(ValueFromPipelineByPropertyName=$True,ParameterSetName = 'ParamQuery')]
        [int]$Length = 10,

        [Parameter(ValueFromPipelineByPropertyName=$True,ParameterSetName = 'ParamQuery')]
        [string]$OrderBy,

        [Parameter(ValueFromPipelineByPropertyName=$True,ParameterSetName = 'ParamQuery')]
        [string]$Sort,

        [Parameter(ValueFromPipelineByPropertyName=$True,ParameterSetName = 'ParamQuery')]
        [string]$DisplayName,

        [Parameter(ValueFromPipelineByPropertyName=$True,ParameterSetName = 'ParamQuery')]
        [int]$Status,

        [Parameter(ValueFromPipelineByPropertyName=$True,ParameterSetName = 'ParamQuery')]
        [string]$Type,

        [Parameter(ParameterSetName = 'ParamShowAtrribs')]
        [switch]$ShowAttributes = $false
    )

    begin {
       
        # Originally had the Endpoint cleanup up in here, however ValueFromPipelineByPropertyName and ValueFromPipeline doesn't get proccessed in the begin block. 
        # Didn't feel like going through the trouble of creating a $InputObject, leaving this in place for notes
    }

    process {

        #Cleanup Path Variable
        $EndPoint = $EndPoint.Replace('//','/')

        If(!($ShowAttributes)){
            
            Write-Verbose $PSBoundParameters.GetEnumerator()
            $URIParams = @{} 

            #Adding Parameters to URIParams
            $URIParams.add('Length', $Length)
            $URIParams.add('Offset', $Offset)
            If ($DisplayName){$URIParams.add('DisplayName', $DisplayName)}
            If ($PSBoundParameters.ContainsKey('Status')){$URIParams.add('Status', $status)}
            If ($Type){$URIParams.add('Type', $type)}
            If ($OrderBy){$URIParams.add('OrderBy', $OrderBy)}
            If ($Sort){$URIParams.add('Sort', $Sort)}

            #Format URIParams to single line
            $URIParams = ($URIParams.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)"}) -join '&'

            Write-Verbose $URIParams

            $URI = "$($ServerName):$($ServerPort)/$global:APIRootPath/$EndPoint/?$URIParams"
        }
        Else{
            Write-Verbose 'ShowAttributes Parameter Was Specified, Formatting URI'
            $URI = "$($ServerName):$($ServerPort)/$global:APIRootPath/$EndPoint/?length=1"
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

        return $Request.data
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

