<#
    .SYNOPSIS
        This module provides functions to interact with the FOLIO API.

    .DESCRIPTION
        This module provides functions to interact with the FOLIO API. It includes functions to authenticate with FOLIO, retrieve records by query, and write record IDs to a CSV file.

    .NOTES
        File Name      : FolioClient-PsModule.psm1
        Author         : FOLIO
        Prerequisite   : PowerShell V5

    .LINK
        GitHub: https://github.com/folio-fse/FolioClient-PsModule
        Powershell Gallery: https://www.powershellgallery.com/packages/FolioClient

    .EXAMPLE
        PS> Import-Module FolioClient
        PS> $folioClient = Get-FolioClient -GatewayUrl https://folio-snapshot-okapi.dev.folio.org -TenantId diku -FolioUsername diku_admin
        Enter password for diku_admin: *****
        PS> Get-FolioRecordsByQuery -FolioClient $folioClient -Path "/inventory/items" -CqlQuery '(materialTypeId=="b3d29557-c74d-403d-a279-a2ef6b3a80f6")' -Limit 10000
        id                                   title
        --                                   -----
        9eb67301-6f6e-468f-9b1a-6134dc39a684 Title 1
        9eb67301-6f6e-468f-9b1a-6134dc39a685 Title 2
        9eb67301-6f6e-468f-9b1a-6134dc39a686 Title 3
        9eb67301-6f6e-468f-9b1a-6134dc39a687 Title 4
        9eb67301-6f6e-468f-9b1a-6134dc39a688 Title 5
#>

function Add-HttpQueryString
{
    <#
        .SYNOPSIS
            This function adds query parameters to a URI.

        .DESCRIPTION
            This function takes a URI and a hashtable of query parameters and returns a URI with the query parameters added.

        .PARAMETER Uri
            The URI to add query parameters to.

        .PARAMETER QueryParams
            A hashtable of query parameters to add to the URI.

        .INPUTS
            None

        .OUTPUTS
            A URI with the query parameters added.

        .EXAMPLE
            PS> Add-HttpQueryString -Uri "https://folio-snapshot-okapi.dev.folio.org" -QueryParams @{ "query" = "(materialTypeId==b3d29557-c74d-403d-a279-a2ef6b3a80f6)" }
            https://folio-snapshot-okapi.dev.folio.org?query=(materialTypeId==b3d29557-c74d-403d-a279-a2ef6b3a80f6)
    #>
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [String]$Uri,

        [Parameter(Mandatory = $true)]
        [Hashtable]$QueryParams
    )

    # Create a http name value collection from an empty string
    $nvCollection = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)

    foreach ($key in $QueryParams.Keys)
    {
        $nvCollection.Add($key, $QueryParams.$key)
    }

    # Build the uri
    $uriRequest = [System.UriBuilder]$uri
    $uriRequest.Query = $nvCollection.ToString()

    return $uriRequest.Uri.AbsoluteUri
}

class FolioClient {
    [string]$GatewayUrl
    [string]$TenantId
    hidden [string]$origTenantId
    [string]$FolioUsername
    hidden [securestring]$FolioPassword
    [string]$AuthToken
    [string]$RefreshToken
    [datetime]$TokenExpiry
    [datetime]$RefreshTokenExpiration
    [Microsoft.PowerShell.Commands.WebRequestSession]$Session
    [bool]$debugMode

    FolioClient([string]$gatewayUrl, [string]$tenantId, [string]$folioUsername, [securestring]$folioPassword = $null, [bool]$debugMode) {
        $this.GatewayUrl = $gatewayUrl
        $this.TenantId = $tenantId
        $this.origTenantId = $($this.TenantId)
        $this.FolioUsername = $folioUsername
        $this.FolioPassword = $folioPassword
        $this.debugMode = $debugMode
        $this.Authenticate()
    }

    [void]Authenticate() {
        if ($null -eq $this.FolioPassword) {
            $this.folioPassword = Read-Host "Enter password for $($this.FolioUsername)" -AsSecureString
        }

        $ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToCoTaskMemUnicode($this.FolioPassword)
        [string]$plainTextPassword = $null
        try {
            # Convert the secure string to plain text
            $plainTextPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($ptr)
        }
        finally {
            # Free the memory used by the secure string pointer
            [System.Runtime.InteropServices.Marshal]::ZeroFreeCoTaskMemUnicode($ptr)
        }
        $authBody = @{
            "username" = $this.folioUsername
            "password" = [string]$plainTextPassword
        } | ConvertTo-Json

        $authUri = [system.UriBuilder]$($this.GatewayUrl)
        $authUri.Path = "/authn/login-with-expiry"

        if ($this.debugMode) {
            write-host "Authenticating with body ('ctrl + c' to exit):"
            write-host $authBody
            Write-Host $authUri.Uri.AbsoluteUri
        }

        $headers = @{
            "x-okapi-tenant" = $this.origTenantId
            "Content-type"   = "application/json"
        }

        $this.Session = New-Object Microsoft.PowerShell.Commands.WebRequestSession

        $RTRSession = New-Object Microsoft.PowerShell.Commands.WebRequestSession
        try {
            $authResponse = Invoke-RestMethod -Method Post -Uri "$($authUri.Uri.AbsoluteUri)" -Body $authBody -Headers $headers -SessionVariable RTRSession
            $this.AuthToken = ($RTRSession.cookies.GetAllCookies() | where-object -Property "Name" -EQ "folioAccessToken").Value
            $this.RefreshToken = ($RTRSession.cookies.GetAllCookies() | where-object -Property "Name" -EQ "folioRefreshToken").Value
            $this.TokenExpiry = [datetime]::Parse($authResponse.accessTokenExpiration)
            $this.RefreshTokenExpiration = [datetime]::Parse($authResponse.refreshTokenExpiration)
            $this.Session = [Microsoft.PowerShell.Commands.WebRequestSession]::new()
            foreach ($crumb in $RTRSession.Cookies.GetAllCookies()) {
                if ($crumb.Name -ilike "%token") {
                    $cookie = [System.Net.Cookie]::new($crumb.Name, $crumb.Value)
                    $this.Session.Cookies.Add($this.GatewayUrl, $cookie)
                }
            }
        } catch {
            $authUri.Path = "/authn/login"
            $authResponse = Invoke-RestMethod -Method Post -Uri "$($authUri.Uri.AbsoluteUri)" -Body $authBody -Headers $headers -SessionVariable RTRSession
            $this.AuthToken = $authResponse.okapiToken
            $this.TokenExpiry = [datetime]::MaxValue
            $this.RefreshTokenExpiration = [datetime]::MaxValue
        }
    }

    [void]RefreshTokenIfNeeded([bool]$force) {
        $refreshUri = [system.UriBuilder]$($this.GatewayUrl)
        $refreshUri.Path = "/authn/refresh"
        if (((Get-Date -AsUTC) -ge $this.TokenExpiry) -or ($force)) {
            $this.Authenticate()
        }
    }

    [hashtable] GetFolioHeaders() {
        $this.RefreshTokenIfNeeded($false)
        $headers = @{
            "x-okapi-tenant" = $this.TenantId
            "x-okapi-token"  = $this.AuthToken
            "Content-type"   = "application/json"
        }
        return $headers
    }

    [void] ResetTenantId() {
        $this.TenantId = $this.origTenantId
    }

    [Microsoft.PowerShell.Commands.WebRequestSession] GetSession() {
        $this.RefreshTokenIfNeeded($false)
        return $this.Session
    }

    [PSCustomObject] InvokeRestMethodWithAuth([string]$path, [string]$method, [hashtable]$headers, [object]$body, [hashtable]$queryParams = @{}) {
        $this.RefreshTokenIfNeeded($false)
        $uri = [system.UriBuilder]$($this.GatewayUrl)
        $uri.Path = $path
        $folioHeaders = $this.GetFolioHeaders()
        foreach ($key in $folioHeaders.Keys) {
            $headers[$key] = $folioHeaders[$key]
        }
        $uriString = Add-HttpQueryString -Uri $($uri.Uri.AbsoluteUri) -QueryParams $queryParams
        try {
            if ($method -eq "GET") {
                return Invoke-RestMethod -Uri $uriString -Method $method -Headers $headers -WebSession $this.Session
            } elseif ($method -eq "POST") {
                return Invoke-RestMethod -Uri $uriString -Method $method -Headers $headers -Body $body -WebSession $this.Session
            } elseif ($method -eq "PUT") {
                return Invoke-RestMethod -Uri $uriString -Method $method -Headers $headers -Body $body -WebSession $this.Session
            } elseif ($method -eq "DELETE") {
                return Invoke-RestMethod -Uri $uriString -Method $method -Headers $headers -WebSession $this.Session
            } else {
                throw "Unsupported HTTP method: $method"
            }
        } catch {
            throw "Request failed: $_"
        }
    }

    [PSCustomObject] Get([string]$endpoint, [string]$query, [hashtable]$queryParams = @{}) {
        return $this.InvokeRestMethodWithAuth($endpoint, "GET", @{}, $null, $queryParams)
    }

    [PSCustomObject] Post([string]$endpoint, [object]$body, [hashtable]$queryParams) {
        return $this.InvokeRestMethodWithAuth($endpoint, "POST", @{}, $body, $queryParams)
    }

    [PSCustomObject] Put([string]$endpoint, [object]$body, [hashtable]$queryParams) {
        return $this.InvokeRestMethodWithAuth($endpoint, "PUT", @{}, $body, $queryParams)
    }

    [PSCustomObject] Delete([string]$endpoint, [string]$query, [hashtable]$queryParams) {
        return $this.InvokeRestMethodWithAuth($endpoint, "DELETE", @{}, $null, $queryParams)
    }

    [PSCustomObject] GetAll([string]$endpoint, [string]$key, [int]$batchsize, [int]$limit, [int]$offset = 0, [string]$query = "cql.allRecords=1 sortBy id", [hashtable]$queryParams = @{}) {
        if (-not $queryParams.ContainsKey("query")) {
            $queryParams["query"] = $query
        }
        if (($limit -lt $batchsize) -and ($limit -ne 0)) {
            $batchsize = $limit
        }
        $queryParams["limit"] = $batchsize
        $queryParams["offset"] = $offset
        $resultsCount = $batchsize
        $allItems = @()
        while (($resultsCount -eq $batchsize) -and ($allItems.Count -lt $limit -or $limit -eq 0)) {
            $response = $this.InvokeRestMethodWithAuth($endpoint, "GET", @{}, $null, $queryParams)
            $resultsCount = $response.$key.Count
            $items = $response.$key
            $allItems += $items
            $queryParams["offset"] += $limit
        }
        return $allItems
    }
}

function Get-FolioClient {
    <#
        .SYNOPSIS
            This function creates a PSObject representing required HTTP request headers for FOLIO authentication.

        .DESCRIPTION
            This function takes a FOLIO API Gateway address, tenant ID, username, and password and returns a PSObject with x-okapi-tenant, Content-type, and x-okapi-token

        .PARAMETER GatewayUrl
            The base URL for the FOLIO API gateway for the tenat you are trying to authenticate to. (eg. https://folio-snapshot-okapi.dev.folio.org)

        .PARAMETER OkapiTenantId
            The tenant ID for the tenant you are trying to authenticate to. (eg. diku)

        .PARAMETER FolioUsername
            The username of the user you are trying to authenticate as.

        .PARAMETER FolioPassword
            The password for the username provided. This parameter is optional. If not provided, you will be prompted for it.

        .INPUTS
            None

        .OUTPUTS
            PSObject representing HTTP headers required for FOLIO API requests (x-okapi-tenant, Content-type, and x-okapi-token).

        .EXAMPLE
            PS> Get-FolioAuthSession -OkapiDomain https://folio-snapshot-okapi.dev.folio.org -OkapiTenantId diku -FolioUsername diku_admin
            Enter password for username: *****

        .EXAMPLE
            PS> $folioClient = Get-FolioClient -GatewayUrl https://folio-snapshot-okapi.dev.folio.org -TenantId diku -FolioUsername diku_admin -FolioPassword $(ConvertTo-SecureString "admin" -AsPlainText -Force)
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string] $GatewayUrl,

        [Parameter(Mandatory = $true)]
        [string] $TenantId,

        [Parameter(Mandatory = $true)]
        [string] $FolioUsername,

        [Parameter(Mandatory = $true)]
        [securestring] $FolioPassword,

        [Parameter(Mandatory = $false)]
        [switch] $DebugMode
    )

    $folioClient = [FolioClient]::new($GatewayUrl, $TenantId, $FolioUsername, $FolioPassword, $DebugMode)
    return $folioClient
}

function Get-FolioRecordsByQuery {
    <#
        .SYNOPSIS
            This function retrieves records from FOLIO based on a CQL query.

        .DESCRIPTION
            This function takes a FOLIO client object, a CQL query, a limit and offset for the query, and returns a list of records.

        .PARAMETER FolioClient
            A PSObject representing the FOLIO client, created by Get-FolioClient.

        .PARAMETER FolioPath
            The HTTP path to the FOLIO endpoint.

        .PARAMETER FolioKey
            The key in the response object that contains the records.

        .PARAMETER CqlQuery
            A CQL query string to filter records by.

        .PARAMETER QueryParams
            A hashtable of additional query parameters to include in the request.

        .PARAMETER Limit
            The maximum number of records to return.

        .PARAMETER Offset
            The number of records to skip before returning results.

        .INPUTS
            None

        .OUTPUTS
            A list of records.

        .EXAMPLE
            PS> $folioClient = Get-FolioClient -GatewayUrl https://folio-snapshot-okapi.dev.folio.org -TenantId diku -FolioUsername diku_admin
            Enter password for diku_admin: *****
            PS> Get-FolioRecordsByQuery -FolioClient $folioClient -Path "/inventory/items" -CqlQuery '(materialTypeId=="b3d29557-c74d-403d-a279-a2ef6b3a80f6")' -Limit 10000 -Offset 0
            id                                   title
            --                                   -----
            2eb67301-6f6e-468f-9b1a-6134dc39a684 Title 1
            3eb67301-6f6e-468f-9b1a-6134dc39a685 Title 2
            4eb67301-6f6e-468f-9b1a-6134dc39a686 Title 3
            5eb67301-6f6e-468f-9b1a-6134dc39a687 Title 4
            6eb67301-6f6e-468f-9b1a-6134dc39a688 Title 5
    #>
    [CmdletBinding()]
    param (
        [Parameter(
            Mandatory = $true,
            HelpMessage = "A PSObject representing the FOLIO client, created by Get-FolioClient."
        )]
        [FolioClient] $FolioClient,

        [Parameter(
            Mandatory = $true,
            HelpMessage = "The HTTP path to the FOLIO endpoint."
        )]
        [string] $FolioPath,

        [Parameter(
            Mandatory = $true,
            HelpMessage = "The key in the response object that contains the records."
        )]
        [string] $FolioKey,

        [Parameter(
            HelpMessage = "A CQL query string to filter records by."
        )]
        [string] $CqlQuery = "cql.allRecords=1 sortBy id",

        [Parameter(
            HelpMessage = "A hashtable of additional query parameters to include in the request."
        )]
        [hashtable] $QueryParams = @{},

        [Parameter(
            HelpMessage = "The limit of records to return at one time from FOLIO."
        )]
        [int] $BatchSize = 100,

        [Parameter(
            HelpMessage = "The maximum number of records to return."
        )]
        [int] $Limit,

        [Parameter(
            HelpMessage = "The number of records to skip before returning results."
        )]
        [int] $Offset = 0

    )

    $folioObjects = $FolioClient.GetAll($FolioPath, $FolioKey, $BatchSize, $Limit, $Offset, $CqlQuery, $QueryParams)
    return $folioObjects
}

function Get-FolioRecordIdsByQuery {
    <#
        .SYNOPSIS
            This function retrieves record IDs from FOLIO based on a CQL query.

        .DESCRIPTION
            This function takes a FOLIO client object, a CQL query, and a limit and offset for the query and returns a list of record IDs.

        .PARAMETER FolioClient
            A PSObject representing the FOLIO client, created by Get-FolioClient.

        .PARAMETER CqlQuery
            A CQL query string to filter records by.

        .PARAMETER Limit
            The maximum number of records to return.

        .PARAMETER Offset
            The number of records to skip before returning results.

        .INPUTS
            None

        .OUTPUTS
            A list of record IDs.

        .EXAMPLE
            PS> $folioClient = Get-FolioClient -GatewayUrl https://folio-snapshot-okapi.dev.folio.org -TenantId diku -FolioUsername diku_admin
            Enter password for diku_admin: *****
            PS> Get-FolioRecordIdsByQuery -FolioClient $folioClient -Path "/inventory/items" -CqlQuery '(materialTypeId=="b3d29557-c74d-403d-a279-a2ef6b3a80f6")' -Limit 10000 -Offset 0
            e9b67301-6f6e-468f-9b1a-6134dc39a684
            9eb67301-6f6e-468f-9b1a-6134dc39a685
            6eb67301-6f6e-468f-9b1a-6134dc39a686
            3eb67301-6f6e-468f-9b1a-6134dc39a687
            2eb67301-6f6e-468f-9b1a-6134dc39a688
    #>
    [CmdletBinding()]
    param (
        [Parameter(
            Mandatory = $true,
            HelpMessage = "A PSObject representing the FOLIO client, created by Get-FolioClient."
        )]
        [FolioClient] $FolioClient,

        [Parameter(
            Mandatory = $true,
            HelpMessage = "The HTTP path to the FOLIO endpoint."
        )]
        [string] $FolioPath,

        [Parameter(
            Mandatory = $true,
            HelpMessage = "The key in the response object that contains the records."
        )]
        [string] $FolioKey,

        [Parameter(
            HelpMessage = "A CQL query string to filter records by."
        )]
        [string] $CqlQuery = "cql.allRecords=1 sortBy id",

        [Parameter(
            HelpMessage = "A hashtable of additional query parameters to include in the request."
        )]
        [hashtable] $QueryParams = @{},

        [Parameter(
            HelpMessage = "The limit of records to return at one time from FOLIO."
        )]
        [int] $BatchSize = 100,

        [Parameter(
            HelpMessage = "The maximum number of records to return."
        )]
        [int] $Limit,

        [Parameter(
            HelpMessage = "The number of records to skip before returning results."
        )]
        [int] $Offset = 0
    )

    if ($Limit -eq 0) {
        $Limit = $null
    }

    $folioObjects = $FolioClient.GetAll($FolioPath, $FolioKey, $BatchSize, $Limit, $Offset, $CqlQuery, $QueryParams)
    return $folioObjects | Select-Object -Property id
}

function Get-FolioRecordIdsToCsvByQuery {
    <#
        .SYNOPSIS
            This function retrieves record IDs from FOLIO based on a CQL query and writes them to a CSV file.

        .DESCRIPTION
            This function takes a FOLIO client object, a CQL query, a limit and offset for the query, and a file path to write the record IDs to.

        .PARAMETER FolioClient
            A PSObject representing the FOLIO client, created by Get-FolioClient.

        .PARAMETER CqlQuery
            A CQL query string to filter records by.

        .PARAMETER Limit
            The maximum number of records to return.

        .PARAMETER Offset
            The number of records to skip before returning results.

        .PARAMETER OutputFilePath
            The path to write the record IDs to.

        .INPUTS
            None

        .OUTPUTS
            A CSV file with record IDs.

        .EXAMPLE
            PS> $folioClient = Get-FolioClient -GatewayUrl https://folio-snapshot-okapi.dev.folio.org -TenantId diku -FolioUsername diku_admin
            Enter password for diku_admin: *****
            PS> Get-FolioRecordIdsToCsvByQuery -FolioClient $folioClient -CqlQuery '(materialTypeId=="b3d29557-c74d-403d-a279-a2ef6b3a80f6")' -Limit 10000 -Offset 0 -OutputFilePath "C:\Users\user\Desktop\record-ids.csv"
    #>
    [CmdletBinding()]
    param (
        [Parameter(
            Mandatory = $true,
            HelpMessage = "A PSObject representing the FOLIO client, created by Get-FolioClient."
        )]
        [FolioClient] $FolioClient,

        [Parameter(
            Mandatory = $true,
            HelpMessage = "The HTTP path to the FOLIO endpoint."
        )]
        [string] $FolioPath,

        [Parameter(
            Mandatory = $true,
            HelpMessage = "The key in the response object that contains the records."
        )]
        [string] $FolioKey,

        [Parameter(
            HelpMessage = "A CQL query string to filter records by."
        )]
        [string] $CqlQuery = "cql.allRecords=1 sortBy id",

        [Parameter(
            HelpMessage = "A hashtable of additional query parameters to include in the request."
        )]
        [hashtable] $QueryParams = @{},

        [Parameter(
            HelpMessage = "The limit of records to return at one time from FOLIO."
        )]
        [int] $BatchSize = 100,

        [Parameter(
            HelpMessage = "The maximum number of records to return."
        )]
        [int] $Limit,

        [Parameter(
            HelpMessage = "The number of records to skip before returning results."
        )]
        [int] $Offset = 0,

        [Parameter(Mandatory = $true)]
        [string] $OutputFilePath,

        [Parameter()]
        [switch] $NoHeaders
    )

    $folioObjects = Get-FolioRecordIdsByQuery -FolioClient $FolioClient -FolioPath $FolioPath -FolioKey $FolioKey -CqlQuery $CqlQuery -QueryParams $QueryParams -BatchSize $BatchSize -Limit $Limit -Offset $Offset
    if ($NoHeaders) {
        $folioObjects | ConvertTo-CSV -NoTypeInformation | Select-Object -Skip 1 | Set-Content -Path $OutputFilePath
    } else {
        $folioObjects | Export-Csv -Path $OutputFilePath -NoTypeInformation
    }
}
