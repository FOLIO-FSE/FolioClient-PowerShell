# Pester test suite for FolioClient module targeting snapshot environment
# Requires PowerShell 5.1+ and Pester 5+

Describe 'FolioClient Integration' {
    BeforeAll {
        Set-StrictMode -Version Latest
        $ErrorActionPreference = 'Stop'

        # Test environment configuration
        $script:GatewayUrl  = 'https://folio-snapshot-okapi.dev.folio.org'
        $script:TenantId    = 'diku'
        $script:Username    = 'diku_admin'
        $script:Password    = 'admin'

        # Choose endpoints/keys known in snapshot
        $script:ItemsPath = '/inventory/items'
        $script:ItemsKey  = 'items'

        # Import the module from the repo
        $modulePath = Join-Path $PSScriptRoot '..' 'src' 'FolioClient' 'FolioClient.psm1'
        Import-Module $modulePath -Force

        # Helper: Build a client (script-scoped scriptblock)
        $script:newClient = {
            $secure = ConvertTo-SecureString $script:Password -AsPlainText -Force
            Get-FolioClient -GatewayUrl $script:GatewayUrl -TenantId $script:TenantId -FolioUsername $script:Username -FolioPassword $secure
        }
    }

    Context 'Authentication' {
        It 'Authenticates and sets tokens/session' {
            $client = & $script:newClient
            $client.AuthToken | Should -Not -BeNullOrEmpty
            $client.Session | Should -Not -BeNullOrEmpty
            $client.TokenExpiry | Should -Not -BeNullOrEmpty
        }
    }

    Context 'Basic GET' {
        It 'Fetches one page of items' {
            $client = & $script:newClient
            $qs = @{ query = 'cql.allRecords=1 sortBy id'; limit = 5; offset = 0 }
            $resp = $client.Get($script:ItemsPath, $qs)
            $resp | Should -Not -BeNullOrEmpty
            $resp.$($script:ItemsKey) | Should -Not -BeNullOrEmpty
            ($resp.$($script:ItemsKey)).Count | Should -BeGreaterThan 0
            $resp.totalRecords | Should -BeGreaterThan 0
        }
    }

    Context 'GetAll pagination (streaming)' {
        It 'Returns exactly the requested limit' {
            $client = & $script:newClient
            $limit = 12
            $batch = 5
            $objects = @(Invoke-FolioGetAll -FolioClient $client -Endpoint $script:ItemsPath -Key $script:ItemsKey -BatchSize $batch -Limit $limit -Offset 0 -Query 'cql.allRecords=1 sortBy id' -QueryParams @{})
            $objects | Should -Not -BeNullOrEmpty
            $objects.Count | Should -Be $limit
            ($objects | Select-Object -First 1).psobject.Properties.Name | Should -Contain 'id'
        }

        It 'Handles larger batch sizes gracefully' {
            $client = & $script:newClient
            $limit = 25
            $batch = 20
            $objects = @(Invoke-FolioGetAll -FolioClient $client -Endpoint $script:ItemsPath -Key $script:ItemsKey -BatchSize $batch -Limit $limit -Offset 0 -Query 'cql.allRecords=1 sortBy id' -QueryParams @{})
            $objects.Count | Should -Be $limit
        }
    }

    Context 'Wrapper functions' {
        It 'Get-FolioRecordsByQuery streams limited records' {
            $client = & $script:newClient
            $records = Get-FolioRecordsByQuery -FolioClient $client -FolioPath $script:ItemsPath -FolioKey $script:ItemsKey -CqlQuery 'cql.allRecords=1 sortBy id' -BatchSize 10 -Limit 15 -Offset 0
            $records | Should -Not -BeNullOrEmpty
            $records.Count | Should -Be 15
            ($records | Select-Object -First 1).psobject.Properties.Name | Should -Contain 'id'
        }

        It 'Get-FolioRecordIdsByQuery returns only ids' {
            $client = & $script:newClient
            $ids = Get-FolioRecordIdsByQuery -FolioClient $client -FolioPath $script:ItemsPath -FolioKey $script:ItemsKey -CqlQuery 'cql.allRecords=1 sortBy id' -BatchSize 10 -Limit 10 -Offset 0
            $ids.Count | Should -Be 10
            foreach ($idObj in $ids) {
                $idObj.id | Should -Match '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
            }
        }

        It 'Get-FolioRecordIdsToCsvByQuery writes a CSV' {
            $client = & $script:newClient
            $tmp = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), 'folio-record-ids.csv')
            Get-FolioRecordIdsToCsvByQuery -FolioClient $client -FolioPath $script:ItemsPath -FolioKey $script:ItemsKey -CqlQuery 'cql.allRecords=1 sortBy id' -BatchSize 10 -Limit 10 -Offset 0 -OutputFilePath $tmp -NoHeaders
            Test-Path $tmp | Should -BeTrue
            ((Get-Content -Path $tmp).Length) | Should -BeGreaterThan 0
            Remove-Item -Path $tmp -Force -ErrorAction SilentlyContinue
        }
    }
}
