
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
  New-BasicAuthCreds -Username 'domain\username' -Password 'P@ssw0rd'
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
  Gets a list of Entity Metrics 
  .DESCRIPTION
  Gets a list of Entity Metrics from the entities/metrics API endpoint. You can also retrieve current measurements for each metric
  .PARAMETER ServerName
  The solarwinds FQDN servername. 
  .PARAMETER WebSession
  An existing Microsoft.PowerShell.Commands.WebRequestSession. Use the New-SWSession to generate a web session
  .PARAMETER ServerPort
  Only required if your solarwinds website is not running on the default port of 443
  .PARAMETER EntityId
  The unique entityID of the entity you want to get metrics from. 
  .PARAMETER Count
  When Count is specified this will return the available measurements from each metric of the entity. A count of 1 will return the most recent measurement.
  .Example
  Returns all metrics for a specified entity
  $WebSession | Get-SWEntityMetrics -EntityId 0_Orion.Nodes_2055
  .Example
  Returns the first measurement for each metric for a specified entity
  $WebSession | Get-SWEntityMetrics -EntityId 0_Orion.Nodes_2055 -Count 1

#>

Function Get-SWEntityMetrics{
    [CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='Low',DefaultParametersetName='ParamDefault')]
    param(
        [Parameter(Mandatory=$true,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [ValidateNotNull()]
        [Alias('Server')]
        [Alias('SolarWindsServer')]
        [string]$ServerName,
        
        [Parameter(Mandatory=$true,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [ValidateNotNull()]
        [Microsoft.PowerShell.Commands.WebRequestSession]$WebSession,

        [Parameter(ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [Alias('Port')]
        [int]$ServerPort = '443',

        [Parameter(Mandatory=$true,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [ValidateNotNull()]
        [string]$EntityId,

        [Parameter(ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [ValidateNotNull()]
        [int]$Count
    )

    begin {
       
        # Originally had the Endpoint cleanup up in here, however ValueFromPipelineByPropertyName, ValueFromPipeline, and ParameterSets do not get proccessed in the begin block. 
        # Also Didn't feel like going through the trouble of creating a $InputObject, leaving this in place for notes
    }

    process {

        #Cleanup Path Variable
        $EndPoint = 'entities'
        $EndPoint = $EndPoint.Replace('//','/')

        Write-Verbose $PSBoundParameters.GetEnumerator()
        $URIParams = @{} 

        #Adding Parameters to URIParams
        If ($PSBoundParameters.ContainsKey('Count')){$URIParams.add('Count', $Count)}
 
        #Format URIParams to single line
        $URIParams = ($URIParams.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)"}) -join '&'
        If ($URIParams){$URIParams = "?$URIParams"}

        Write-Verbose $URIParams

        $URI = "$($ServerName):$($ServerPort)/$global:APIRootPath/$EndPoint/$EntityId/metrics/$URIParams"

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
  Gets measurements from a specific metric entity id
  .DESCRIPTION
  Gets measurements from a specific metric entity id from the metrics/ API endpoint.
  .PARAMETER ServerName
  The solarwinds FQDN servername. 
  .PARAMETER WebSession
  An existing Microsoft.PowerShell.Commands.WebRequestSession. Use the New-SWSession to generate a web session
  .PARAMETER ServerPort
  Only required if your solarwinds website is not running on the default port of 443
  .PARAMETER EntityId
  The unique entityID of the entity you want to get metrics from. 
  .PARAMETER MetricId
  The unique entityID of the entity you want to get metrics from. 
  .PARAMETER Count
  When Count is specified this will return the available measurements from each metric of the entity. A count of 1 will return the most recent measurement.
  .PARAMETER Resolution
  Since there is no official documentation from SolarWinds, I beleive this parameter only applies to the perfstack UI when returning measurements.
  .PARAMETER StartDate
  Sepecify the start date and time range to retrieve measurements from. EndDate is required with this parameter. A valid date time is required.
  .PARAMETER EndDate
  Sepecify the end date and time range to retrieve measurements from. StartDate is required with this parameter. A valid date time is required.
  .EXAMPLE
  Gets the CPU MaxLoad for an entity
  $WebSession | Get-SWMeasurement -EntityId 0_Orion.Nodes_2055 -MetricId Orion.CPULoad.MaxLoad
  .EXAMPLE
  Gets the CPU MaxLoad for an entity for the last hour
  $Start = (Get-Date).AddHours(-1)
  $End = Get-Date
  $WebSession | Get-SWMeasurement -EntityId 0_Orion.Nodes_2055 -MetricId Orion.CPULoad.MaxLoad -StartDate $Start -EndDate $End
  .EXAMPLE
  Gets the last 3 CPU MaxLoad measurements for an entity
  $Start = (Get-Date).AddHours(-1)
  $End = Get-Date
  $WebSession | Get-SWMeasurement -EntityId 0_Orion.Nodes_2055 -MetricId Orion.CPULoad.MaxLoad -Count 3

#>

Function Get-SWMeasurement{
    [CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='Low',DefaultParametersetName='ParamDefault')]
    param(
        [Parameter(Mandatory=$true,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [ValidateNotNull()]
        [Alias('Server')]
        [Alias('SolarWindsServer')]
        [string]$ServerName,
        
        [Parameter(Mandatory=$true,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [ValidateNotNull()]
        [Microsoft.PowerShell.Commands.WebRequestSession]$WebSession,

        [Parameter(ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [Alias('Port')]
        [int]$ServerPort = '443',

        [Parameter(Mandatory=$true,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [ValidateNotNull()]
        [string]$EntityId,

        [Parameter(Mandatory=$true,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [ValidateNotNull()]
        [string]$MetricId,

        [Parameter(ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [ValidateNotNull()]
        [int]$Count,

        [Parameter(ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [ValidateNotNull()]
        [int]$Resolution,

        [Parameter(ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True,ParameterSetName = 'ParamDate')]
        [ValidateNotNull()]
        [datetime]$StartDate,

        [Parameter(ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True,ParameterSetName = 'ParamDate')]
        [ValidateNotNull()]
        [datetime]$EndDate

    )

    begin {
       
        # Originally had the Endpoint cleanup up in here, however ValueFromPipelineByPropertyName, ValueFromPipeline, and ParameterSets do not get proccessed in the begin block. 
        # Also Didn't feel like going through the trouble of creating a $InputObject, leaving this in place for notes
    }

    process {

        #Cleanup Path Variable
        $EndPoint = 'metrics'
        $EndPoint = $EndPoint.Replace('//','/')

        Write-Verbose $PSBoundParameters.GetEnumerator()

        $IDParams = "$EntityId-$MetricId"
        
        Write-Verbose $IDParams

        $URIParams = @{} 

        #Adding Parameters to URIParams
        If ($PSBoundParameters.ContainsKey('Count')){$URIParams.add('Count', $Count)}
        If ($PSBoundParameters.ContainsKey('Resolution')){$URIParams.add('Resolution', $Resolution)}
        
        If ($StartDate){
            $Start = Get-Date $StartDate -format "yyyy-MM-ddTHH:mm:ss:fffZ"
            $URIParams.add('StartDate', $Start)
        }
        If ($EndDate){
            $End = Get-Date $EndDate -format "yyyy-MM-ddTHH:mm:ss:fffZ"
            $URIParams.add('EndDate', $End)
        }

        #Format URIParams to single line
        $URIParams = ($URIParams.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)"}) -join '&'
        If ($URIParams){$URIParams = "?$URIParams"}

        
        Write-Verbose $URIParams

        $URI = "$($ServerName):$($ServerPort)/$global:APIRootPath/$EndPoint/$IDParams/$URIParams"

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
  Gets a list of Entity relationships 
  .DESCRIPTION
  Gets a list of relationships from an entity such as applications, groups, hosts, datacenters, volumes, etc.
  .PARAMETER ServerName
  The solarwinds FQDN servername. 
  .PARAMETER WebSession
  An existing Microsoft.PowerShell.Commands.WebRequestSession. Use the New-SWSession to generate a web session
  .PARAMETER ServerPort
  Only required if your solarwinds website is not running on the default port of 443
  .PARAMETER EntityId
  The unique entityID of the entity you want to get metrics from. 
  .Example
  Returns all relationships for a specified entity
  $websession | Get-SWEntityRelationships -EntityId 0_Orion.Nodes_2055

#>

Function Get-SWEntityRelationships{
    [CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='Low',DefaultParametersetName='ParamDefault')]
    param(
        [Parameter(Mandatory=$true,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [ValidateNotNull()]
        [Alias('Server')]
        [Alias('SolarWindsServer')]
        [string]$ServerName,
        
        [Parameter(Mandatory=$true,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [ValidateNotNull()]
        [Microsoft.PowerShell.Commands.WebRequestSession]$WebSession,

        [Parameter(ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [Alias('Port')]
        [int]$ServerPort = '443',

        [Parameter(Mandatory=$true,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [ValidateNotNull()]
        [string]$EntityId
    )

    begin {
       
        # Originally had the Endpoint cleanup up in here, however ValueFromPipelineByPropertyName, ValueFromPipeline, and ParameterSets do not get proccessed in the begin block. 
        # Also Didn't feel like going through the trouble of creating a $InputObject, leaving this in place for notes
    }

    process {

        #Cleanup Path Variable
        $EndPoint = 'relationships'
        $EndPoint = $EndPoint.Replace('//','/')

        $URI = "$($ServerName):$($ServerPort)/$global:APIRootPath/entities/$EntityId/$EndPoint"

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

