# FOLIO for PowerShell

This module provides cmdlets for performing basic API interactions with a [FOLIO LSP](https://folio.org) environment. It is inspired by the FOLIO-FSE python [FolioClient](https://github.com/folio-fse/FolioClient) library.

For more information about the FOLIO LSP environment and its API, please refer to the [FOLIO API documentation](https://dev.folio.org/reference/api).

## Installation

```powershell
# From PowerShell Gallery (when published)
Install-Module -Name FolioClient

# From local path
Import-Module -Path ./src/FolioClient/FolioClient.psd1
```

## Quick Start

```powershell
# Create a FOLIO client
$folioClient = Get-FolioClient `
    -GatewayUrl "https://folio-snapshot-okapi.dev.folio.org" `
    -TenantId "diku" `
    -FolioUsername "diku_admin"

# You will be prompted for a password. Alternatively, provide it directly:
$password = ConvertTo-SecureString "admin" -AsPlainText -Force
$folioClient = Get-FolioClient `
    -GatewayUrl "https://folio-snapshot-okapi.dev.folio.org" `
    -TenantId "diku" `
    -FolioUsername "diku_admin" `
    -FolioPassword $password

# Retrieve records by CQL query
$items = Get-FolioRecordsByQuery `
    -FolioClient $folioClient `
    -FolioPath "/inventory/items" `
    -FolioKey "items" `
    -CqlQuery '(materialTypeId=="b3d29557-c74d-403d-a279-a2ef6b3a80f6")' `
    -Limit 100

# Export record IDs to CSV
Get-FolioRecordIdsToCsvByQuery `
    -FolioClient $folioClient `
    -FolioPath "/inventory/items" `
    -FolioKey "items" `
    -OutputFilePath "record-ids.csv" `
    -Limit 1000
```

## Cmdlets Included

### Get-FolioClient
Creates a FolioClient instance for authenticating with and making requests to FOLIO.

**Parameters:**
- `GatewayUrl` (required): The FOLIO API gateway URL (e.g., `https://folio-snapshot-okapi.dev.folio.org`)
- `TenantId` (required): The tenant ID (e.g., `diku`)
- `FolioUsername` (required): The username for authentication
- `FolioPassword` (optional): The password as a secure string. If not provided, you will be prompted
- `DebugMode` (optional): Enable debug output

### Get-FolioRecordsByQuery
Retrieves full records from a FOLIO endpoint using a CQL query.

**Parameters:**
- `FolioClient` (required): A FolioClient instance
- `FolioPath` (required): The API endpoint path (e.g., `/inventory/items`)
- `FolioKey` (required): The key in the response containing records (e.g., `items`)
- `CqlQuery` (optional): CQL query string (default: `cql.allRecords=1 sortBy id`)
- `Limit` (optional): Maximum number of records to return (0 = all)
- `Offset` (optional): Number of records to skip
- `BatchSize` (optional): Records per request (default: 100)
- `QueryParams` (optional): Additional query parameters

**Returns:** Array of record objects

### Get-FolioRecordIdsByQuery
Retrieves only the record IDs from a FOLIO endpoint using a CQL query.

**Parameters:** Same as `Get-FolioRecordsByQuery`

**Returns:** Array of ID strings

### Get-FolioRecordIdsToCsvByQuery
Retrieves record IDs and exports them to a CSV file.

**Parameters:**
- All parameters from `Get-FolioRecordIdsByQuery`
- `OutputFilePath` (required): Path where the CSV file will be written
- `NoHeaders` (optional): Omit column headers from the CSV

### Invoke-FolioGetAll
Streams records from a FOLIO endpoint with automatic pagination (generator-like behavior). Items are yielded one-at-a-time via the pipeline without accumulating all results in memory.

**Parameters:**
- `FolioClient` (required): A FolioClient instance
- `Endpoint` (required): The API endpoint path (e.g., `/inventory/items`)
- `Key` (required): The key in the response containing records (e.g., `items`)
- `Query` (optional): CQL query string (default: `cql.allRecords=1 sortBy id`)
- `BatchSize` (optional): Records per request (default: 100)
- `Limit` (optional): Maximum total records to return (0 = all)
- `Offset` (optional): Starting record offset (default: 0)
- `QueryParams` (optional): Additional query parameters hashtable

**Returns:** Stream of record objects (one per pipeline object)

**Usage - Stream without collecting:**
```powershell
Invoke-FolioGetAll -FolioClient $folioClient -Endpoint '/inventory/items' -Key 'items' -Limit 1000 | `
    Where-Object { $_.status -eq 'Available' } | `
    ForEach-Object { Export-Item $_ }
```

**Usage - Collect results when needed:**
```powershell
$items = @(Invoke-FolioGetAll -FolioClient $folioClient -Endpoint '/inventory/items' -Key 'items' -Limit 1000)
```

## FolioClient Class Methods

The `FolioClient` class provides low-level methods for HTTP operations:

- `Get(endpoint, queryParams)` - HTTP GET request
- `Post(endpoint, body, queryParams)` - HTTP POST request
- `Put(endpoint, body, queryParams)` - HTTP PUT request
- `Patch(endpoint, body, queryParams)` - HTTP PATCH request
- `Delete(endpoint, queryParams)` - HTTP DELETE request

For retrieving paginated results with streaming support, use the `Invoke-FolioGetAll` function instead.

## Examples

### Example 1: Retrieve All Items of a Material Type

```powershell
$folioClient = Get-FolioClient -GatewayUrl $url -TenantId $tenant -FolioUsername $username

$items = @(Invoke-FolioGetAll `
    -FolioClient $folioClient `
    -Endpoint "/inventory/items" `
    -Key "items" `
    -Query '(materialTypeId=="book-material-type-id")' `
    -BatchSize 100)

Write-Host "Retrieved $($items.Count) items"
```

### Example 2: Export Item IDs to CSV

```powershell
Get-FolioRecordIdsToCsvByQuery `
    -FolioClient $folioClient `
    -FolioPath "/inventory/items" `
    -FolioKey "items" `
    -CqlQuery '(status.name=="Available")' `
    -OutputFilePath "available-items.csv"
```

### Example 3: Streaming Large Result Sets

```powershell
# Stream without collecting (processes one item at a time, minimal memory)
$total = 0
Invoke-FolioGetAll `
    -FolioClient $folioClient `
    -Endpoint "/inventory/items" `
    -Key "items" `
    -Limit 10000 | `
    ForEach-Object { 
        $total++
        # Process each item immediately without storing all 10,000 in memory
        if ($_.status -eq 'Available') { Write-Host "Available: $($_.title)" }
    }
Write-Host "Processed $total items"
```

### Example 4: Using Low-Level API Methods

```powershell
# Direct API call
$holdings = $folioClient.Get("/inventory/holdings", @{ limit = 50 })

# POST example
$newRecord = @{ title = "New Title" } | ConvertTo-Json
$result = $folioClient.Post("/inventory/items", $newRecord, @{})
```

## Tenant Switching

The FolioClient supports switching between tenants:

```powershell
# Switch to a different tenant
$folioClient.TenantId = "different-tenant"

# Reset to the original tenant
$folioClient.ResetTenantId()
```

## Error Handling

The module will throw exceptions if authentication fails or API requests encounter errors:

```powershell
try {
    $items = Get-FolioRecordsByQuery -FolioClient $folioClient -FolioPath "/inventory/items" -FolioKey "items"
} catch {
    Write-Host "Error: $_"
}
```

## Notes

- **Password Security**: Passwords are handled using PowerShell's SecureString type. If you provide a password directly, consider using `ConvertTo-SecureString` with the `-AsPlainText` flag only in development environments.
- **Token Refresh**: The client automatically refreshes authentication tokens before they expire.
- **Streaming Pagination**: The `Invoke-FolioGetAll` function handles pagination automatically with streaming support—items are yielded one-at-a-time without accumulating all results in memory. This is ideal for large result sets.
- **Batch Size**: The default batch size is 100 records per request. Increase or decrease based on your API's limits and memory constraints.
- **Lazy Loading**: Use `Invoke-FolioGetAll` to process items as they arrive without loading entire datasets into memory.

## Requirements

- PowerShell 5.1 or higher
- Network connectivity to a FOLIO instance

## License

MIT License - See [LICENSE](LICENSE) for details

## Contributing

Contributions are welcome! Please refer to the main repository at [FOLIO-FSE/FolioClient-PowerShell](https://github.com/FOLIO-FSE/FolioClient-PowerShell) 