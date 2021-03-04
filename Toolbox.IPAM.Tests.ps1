#Requires -Modules Pester
#Requires -Version 5.1

BeforeDiscovery {
    # used by inModuleScope
    $testModule = $PSCommandPath.Replace('.Tests.ps1', '.psm1')
    $testModuleName = $testModule.Split('\')[-1].TrimEnd('.psm1')

    Remove-Module $testModuleName -Force -Verbose:$false -EA Ignore
    Import-Module $testModule -Force -Verbose:$false
}
BeforeAll {
    $testParams = @{
        Environment = 'Test'
    }

    $testBody = @{
        FixedAddress = @(
            # one PSCustomObject to verify compatibility with HashTable
            [PSCustomObject]@{
                ipv4addr      = '10.20.32.1'
                mac           = '00:00:00:00:00:01'
                name          = 'PesterTest1'
                ddns_hostname = 'PesterTest1'
                match_client  = 'MAC_ADDRESS'
                enable_ddns   = $true
                comment       = 'Pester test from PowerShell'
            }
            @{
                ipv4addr      = '10.20.32.2'
                mac           = '00:00:00:00:00:02'
                name          = 'PesterTest2'
                ddns_hostname = 'PesterTest2'
                match_client  = 'MAC_ADDRESS'
                enable_ddns   = $true
                comment       = 'Pester test from PowerShell'
            }
            @{
                ipv4addr      = '10.20.32.3'
                mac           = '00:00:00:00:00:03'
                name          = 'PesterTest3'
                ddns_hostname = 'PesterTest3'
                match_client  = 'MAC_ADDRESS'
                enable_ddns   = $true
                comment       = 'Pester test from PowerShell'
            }
            @{
                ipv4addr      = '10.20.32.4'
                mac           = '00:00:00:00:00:04'
                name          = 'PesterTest4'
                ddns_hostname = 'PesterTest4'
                match_client  = 'MAC_ADDRESS'
                enable_ddns   = $true
                comment       = 'Pester test from PowerShell'
            }
        )
    }

    $testRemoveFixedAddresses = {
        $testGetParams = @{
            Type   = 'FixedAddress'
            Filter = $testBody.FixedAddress.ipv4addr.ForEach( { "ipv4addr=$_" })
        }
        Get-IpamObjectHC @testParams @testGetParams | Remove-IpamObjectHC @testParams -NoServiceRestart
    }
}
AfterAll {
    Restart-IpamServiceHC @testParams
}
Describe 'New-IpamObjectHC' {
    Context 'mandatory parameters' {
        It '<_>' -ForEach @(
            'Type',
            'Body',
            'Environment'
        ) {
            (
                Get-Command -Name New-IpamObjectHC
            ).Parameters[$_].Attributes.Mandatory | Should -BeTrue
        } 
    }
    Context 'FixedAddress' {
        BeforeAll {
            & $testRemoveFixedAddresses
        }
        It "add a new object when it doesn't exist" {
            $Actual = New-IpamObjectHC @testParams -Type FixedAddress -Body $testBody.FixedAddress[0] -NoServiceRestart
            $Actual | Should -HaveCount 1
        } 
        It 'convert body properties to lower case and add the object' {
            $testBodyUpperCase = $testBody.FixedAddress[1]

            $testBodyUpperCase.Remove('match_client')
            $testBodyUpperCase.Add('MATCH_CLIENT', 'MAC_ADDRESS')

            $Actual = New-IpamObjectHC @testParams -Type FixedAddress -Body $testBodyUpperCase  -NoServiceRestart
            $Actual | Should -HaveCount 1
        } 
        It 'convert NULL values to empty string' {
            $testNullValue = $testBody.FixedAddress[3]

            $testNullValue.Remove('ddns_hostname')
            $testNullValue.Add('ddns_hostname', $null)

            $Actual = New-IpamObjectHC @testParams -Type FixedAddress -Body $testNullValue  -NoServiceRestart
            $Actual | Should -HaveCount 1
        } 
        It "when the object already exists an error is thrown" {
            { New-IpamObjectHC @testParams -Type FixedAddress -Body $testBody.FixedAddress[0] -NoServiceRestart -EA Stop } |
            Should -Throw -PassThru |
            Should -BeLike "*API error: MAC address $($testBody.FixedAddress[0].mac) is used in two fixed addresses $($testBody.FixedAddress[0].ipv4addr)*"
        } 
        It 'add a new object and request specific ReturnFields' {
            & $testRemoveFixedAddresses

            $Actual = New-IpamObjectHC @testParams -Type FixedAddress -Body $testBody.FixedAddress[0] -NoServiceRestart -Property comment, name
            $Actual.comment | Should -Be $testBody.FixedAddress[0].comment
            $Actual.name | Should -Be $testBody.FixedAddress[0].name
            $Actual.enable_ddns | Should -BeNullOrEmpty -Because 'other properties are not expected'
        } 
        It "when ReturnField contains a space an error is thrown" {
            { New-IpamObjectHC @testParams -Type FixedAddress -Body $testBody.FixedAddress[0] -Property 'com ment' -NoServiceRestart } |
            Should -Throw -PassThru |
            Should -BeLike "*The property 'com ment' cannot contain spaces.*"
        } 
        It 'add multiple objects at once' {
            & $testRemoveFixedAddresses

            $Actual = New-IpamObjectHC @testParams -Type FixedAddress -Body $testBody.FixedAddress -NoServiceRestart
            $Actual | Should -HaveCount $testBody.FixedAddress.Count
        } 
        It 'throw non terminating errors when objects already exist' {
            $Error.Clear()
            New-IpamObjectHC @testParams -Type FixedAddress -Body $testBody.FixedAddress -NoServiceRestart -EA SilentlyContinue
            $Error | Should -HaveCount $testBody.FixedAddress.Count
        } 
        It 'accept pipeline input for the Body' {
            & $testRemoveFixedAddresses

            $Actual = $testBody.FixedAddress | New-IpamObjectHC @testParams -Type FixedAddress -NoServiceRestart
            $Actual | Should -HaveCount $testBody.FixedAddress.Count
        } 
    }
}
Describe 'Remove-IpamObjectHC' {
    BeforeAll {
        & $testRemoveFixedAddresses
    }
    Context 'mandatory parameters' {
        It '<_>' -ForEach @(
            'ReferenceObject',
            'Environment'
        ) {
            (
                Get-Command -Name Remove-IpamObjectHC
            ).Parameters[$_].Attributes.Mandatory | Should -BeTrue
        }
    }
    Context 'throw an error when' {
        It "the ReferenceObject object string contains a space" {
            { Remove-IpamObjectHC @testParams -ReferenceObject 'in correct' -NoServiceRestart } |
            Should -Throw -PassThru |
            Should -BeLike "*the ReferenceObject 'in correct' cannot contain spaces*"
        } 
        It "the ReferenceObject object has no '_ref' property" {
            { [PSCustomObject]@{
                    Name = 'Something'
                } | Remove-IpamObjectHC @testParams } |
            Should -Throw -PassThru |
            Should -BeLike "*The property '_ref' cannot be found on this object*"
        } 
    }
    Context 'remove an object when' {
        It 'one needs to be removed' {
            $Actual = New-IpamObjectHC @testParams -Type FixedAddress -Body $testBody.FixedAddress[0] -NoServiceRestart
            $Actual | Should -Not -BeNullOrEmpty

            { 
                Remove-IpamObjectHC @testParams -ReferenceObject $Actual._ref -NoServiceRestart 
            } | 
            Should -Not -Throw
        } 
        It 'multiple need to be removed' {
            $Actual = New-IpamObjectHC @testParams -Type FixedAddress -Body $testBody.FixedAddress -NoServiceRestart
            $Actual | Should -HaveCount $testBody.FixedAddress.count

            { 
                Remove-IpamObjectHC @testParams -ReferenceObject $Actual._ref -NoServiceRestart 
            } | 
            Should -Not -Throw
        } 
        It 'provided by the pipeline' {
            { 
                New-IpamObjectHC @testParams -Type FixedAddress -Body $testBody.FixedAddress -NoServiceRestart |
                Remove-IpamObjectHC @testParams -NoServiceRestart 
            } | 
            Should -Not -Throw
        } 
    }
}
Describe 'Get-IpamObjectHC' {
    Context 'mandatory parameters' {
        It '<_>' -ForEach @(
            'Environment'
        ) {
            (
                Get-Command -Name Get-IpamObjectHC
            ).Parameters[$_].Attributes.Mandatory | Should -BeTrue
        }
    }
    Context 'throw an error when' {
        It "parameter 'Filter' contains a space" {
            { 
                Get-IpamObjectHC @testParams -Type FixedAddress -Filter 'mac=In correct' 
            } |
            Should -Throw "*cannot contain spaces*"
        } 
        It "parameter 'ReturnField' contains a space" {
            { 
                Get-IpamObjectHC @testParams -Type FixedAddress -Property 'In correct' 
            } |
            Should -Throw "*cannot contain spaces*"
        } 
    }
    Context 'FixedAddress' {
        BeforeAll {
            & $testRemoveFixedAddresses

            $Actual = $testBody.FixedAddress | New-IpamObjectHC @testParams -Type FixedAddress -NoServiceRestart
            $Actual | Should -HaveCount $testBody.FixedAddress.Count
        }
        Context 'get an object with ReferenceObject as' {
            Context 'string' {
                It 'one string not piped' {
                    Get-IpamObjectHC @testParams -ReferenceObject $Actual[0]._ref | Should -HaveCount 1
                } 
                It 'one string piped' {
                    $Actual[0]._ref | Get-IpamObjectHC @testParams | 
                    Should -HaveCount 1
                } 
                It 'multiple strings not piped' {
                    Get-IpamObjectHC @testParams -ReferenceObject $Actual._ref | Should -HaveCount $Actual._ref.count
                } 
                It 'multiple strings piped' {
                    $Actual._ref | Get-IpamObjectHC @testParams | 
                    Should -HaveCount $Actual._ref.count
                } 
            }
            Context 'object' {
                It 'one object not piped' {
                    Get-IpamObjectHC @testParams -ReferenceObject $Actual[0] | 
                    Should -HaveCount 1
                } 
                It 'one object piped' {
                    $Actual[0] | Get-IpamObjectHC @testParams | 
                    Should -HaveCount 1
                } 
                It 'multiple objects not piped' {
                    Get-IpamObjectHC @testParams -ReferenceObject $Actual | 
                    Should -HaveCount $Actual._ref.count
                } 
                It 'multiple objects piped' {
                    $Actual | Get-IpamObjectHC @testParams |
                    Should -HaveCount $Actual._ref.count
                } 
            }
            Context "when the object doesn't exist" {
                It 'throw an error' {
                    { 
                        Get-IpamObjectHC @testParams -ReferenceObject 'nonexisting' 
                    } |
                    Should -Throw "*No default properties defined for object type 'nonexisting'*"
                } 
                It 'throw an error when a Property is given' {
                    { 
                        Get-IpamObjectHC @testParams -ReferenceObject 'nonexisting' -Property 'comment' -EA Stop 
                    } |
                    Should -Throw "*API error: Unknown object type (nonexisting)*"
                } 
            }
        }
        Context 'get an object with Type' {
            It 'without ReturnField' {
                Get-IpamObjectHC @testParams -Type FixedAddress | 
                Should -Not -BeNullOrEmpty
            } 
            It 'with ReturnField' {
                Get-IpamObjectHC @testParams -Type FixedAddress -Property Comment | Should -Not -BeNullOrEmpty
            } 
            It 'with Filter' {
                Get-IpamObjectHC @testParams -Type FixedAddress -Property Comment -Filter "ipv4addr=$($testBody.FixedAddress[0].ipv4addr)" | Should -Not -BeNullOrEmpty
            } 
        }
    }
    Context 'range' {
        It 'get ranges' {
            $testRanges = Get-IpamObjectHC @testParams -Type Range
            $testRanges | Should -Not -BeNullOrEmpty
        } 
    }
}
Describe 'Update-IpamObjectHC' {
    BeforeAll {
        & $testRemoveFixedAddresses
        $testFixedAddresses = $testBody.FixedAddress | 
        New-IpamObjectHC @testParams -Type FixedAddress -NoServiceRestart
    }
    Context 'update one object and set a value for' {
        It 'a single field' {
            $Actual = Update-IpamObjectHC @testParams -ReferenceObject $testFixedAddresses[0] -Body @{
                enable_ddns = -not $testFixedAddresses[0].enable_ddns
            } -NoServiceRestart

            $Actual.enable_ddns | 
            Should -Be (-not $testFixedAddresses[0].enable_ddns)
        } 
        It 'multiple fields' {
            $testBody = @{
                comment = $testFixedAddresses[0].comment += ' updated'
                name    = $testFixedAddresses[0].name += ' updated'
            }

            $Actual = Update-IpamObjectHC @testParams -ReferenceObject $testFixedAddresses[0] -Body $testBody -NoServiceRestart

            $testBody.GetEnumerator().ForEach( {
                    $Actual.($_.key) | Should -Be $_.value
                })
        } 
    }
    Context 'update multiple objects and set a value for' {
        It 'a single field' {
            $testComment = 'Pester test updated comment field'

            $Actual = Update-IpamObjectHC @testParams -ReferenceObject $testFixedAddresses -Body @{
                comment = $testComment
            } -NoServiceRestart

            $Actual.ForEach( {
                    $_.comment | Should -Be $testComment
                })
        } 
        It 'multiple fields' {
            $testComment = 'Pester test'

            $testBody = @{
                comment     = $testComment
                enable_ddns = $true
            }

            $Actual = Update-IpamObjectHC @testParams -ReferenceObject $testFixedAddresses -Body $testBody -NoServiceRestart

            foreach ($A in $Actual) {
                $testBody.GetEnumerator().ForEach( {
                        $A.($_.key) | Should -Be $_.value
                    })
            }
        } 
    }
    It 'update fields by piping the ReferenceObject' {
        $testComment = 'Pester test'

        $testBody = @{
            comment     = $testComment
            enable_ddns = $true
        }

        $Actual = $testFixedAddresses | Update-IpamObjectHC @testParams -Body $testBody -NoServiceRestart

        foreach ($A in $Actual) {
            $testBody.GetEnumerator().ForEach( {
                    $A.($_.key) | Should -Be $_.value
                })
        }
    } 
}


