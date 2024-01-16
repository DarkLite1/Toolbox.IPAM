#Requires -Version 5.1
#Requires -Modules Microsoft.PowerShell.Utility, ActiveDirectory

Set-StrictMode -Version Latest

Function ConvertTo-HashTableHC {
    [CmdletBinding()]
    [OutputType('HashTable')]
    Param (
        [Parameter(ValueFromPipeline)]
        $InputObject
    )

    Process {
        if ($null -eq $InputObject) {
            return $null
        }

        if ($InputObject -is [System.Collections.IEnumerable] -and $InputObject -isNot [String]) {
            $collection = @(
                foreach ($object in $InputObject) {
                    ConvertTo-HashtableHC -InputObject $object
                }
            )

            Write-Output -NoEnumerate $collection
        }
        elseif ($InputObject -is [PSObject]) {
            $hash = @{ }
            foreach ($property in $InputObject.PSObject.Properties) {
                $hash[$property.Name] = ConvertTo-HashtableHC -InputObject $property.Value
            }
            $hash
        }
        else {
            $InputObject
        }
    }
}
Function Import-CredentialsHC {
    <#
    .SYNOPSIS
        Create a PSCredential object.

    .DESCRIPTION
        Create a PSCredential object with a user name and password that can be
        used for authentication via 'CredSsp'.

    .PARAMETER SamAccountName
        The SAM Account Name used to logon to the domain.

    .PARAMETER Password
        Plain text or a hashed file. Keep in mind that the hashed file can only
        be decrypted by the user that hashed it. A part of the Windows profile
        is used to decipher the hash.

    .EXAMPLE
        $Cred = Import-CredentialsHC -SamAccountName 'bob' -Password '123'
        Creates the PSCredential object '$Cred' for the user 'bob' with his
        password '123'.

    .EXAMPLE
        $Cred = Import-CredentialsHC 'bob' 'T:\Input\bob.txt'
        Creates the PSCredential object '$Cred' for the user 'bob' with his
        password in the hashed file "T:\Input\bob.txt".
    #>

    [CmdletBinding()]
    Param (
        [parameter(Mandatory, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]$SamAccountName,
        [parameter(Mandatory, Position = 1)]
        [ValidateNotNullOrEmpty()]
        [String]$Password
    )

    Process {
        If (-not (Get-ADUser -Filter { SamAccountName -eq $SamAccountName })) {
            throw "Import-CredentialsHC: The SamAccountName '$SamAccountName' is incorrect"
        }

        if (-not ((Get-ADUser -Identity $SamAccountName).Enabled)) {
            throw "Import-CredentialsHC: The account '$SamAccountName' is disabled"
        }

        if ((Get-ADUser -Identity $SamAccountName -Properties LockedOut).LockedOut) {
            throw "Import-CredentialsHC: The account '$SamAccountName' is locked-out"
        }

        if (Test-Path $Password -PathType Leaf) {
            try {
                $Pwd = Get-Content $Password | ConvertTo-SecureString -Force -EA Stop
                $Credentials = New-Object System.Management.Automation.PSCredential -ArgumentList $SamAccountName, $Pwd
            }
            catch {
                throw "Import-CredentialsHC: The password has been hashed with another Windows profile (user) then the Windows account now in use
                (all 3 users/owners need to be the same)
                - Script account :`t $env:USERNAME
                - SamAccountName :`t $SamAccountName
                - Password file  :`t $Password"
            }
        }
        else {
            $Pwd = $Password | ConvertTo-SecureString -AsPlainText -Force
            $Credentials = New-Object System.Management.Automation.PSCredential -ArgumentList $SamAccountName, $Pwd
        }

        if (
            (New-Object directoryservices.directoryentry "", $SamAccountName, $($Credentials.GetNetworkCredential().Password)).psbase.name -ne $null
        ) {
            Write-Output $Credentials
        }
        else {
            throw "Import-CredentialsHC: The password for the user '$SamAccountName' is not valid"
        }
    }
}

#region Import credentials form passwords.json file
$PasswordFile = "$PSScriptRoot\Passwords.json"

if (-not (Test-Path -Path $PasswordFile -PathType Leaf)) {
    throw "File 'Passwords.json' not found in the module folder. Please add your credentials to this file and save it in the folder '$PSScriptRoot'."
}



$Credentials = Get-Content -Path $PasswordFile -Raw -EA Stop |
ConvertFrom-Json -EA Stop | ConvertTo-HashTableHC
#endregion

$EnvironmentParameter = {
    $ParameterName = 'Environment'
    $ParameterValues = $Credentials.Keys

    $CustomAttribute = New-Object System.Management.Automation.ParameterAttribute
    $CustomAttribute.Position = 1
    $CustomAttribute.Mandatory = $true

    $AttributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
    $AttributeCollection.Add($CustomAttribute)

    $AttribValidateSet = New-Object System.Management.Automation.ValidateSetAttribute($ParameterValues)
    $AttributeCollection.Add($AttribValidateSet)

    $EnvironmentParam = New-Object System.Management.Automation.RuntimeDefinedParameter(
        $ParameterName, [String], $AttributeCollection)

    $ParamDictionary = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary
    $ParamDictionary.Add($ParameterName, $EnvironmentParam)
    $ParamDictionary
}

$DefaultProperties = @{
    'fixedaddress' = @(
        'mac', 'name', 'ipv4addr', 'match_client', 'ddns_domainname', 'ddns_hostname', 'device_type', 'device_vendor',
        'enable_ddns', 'extattrs', 'disable', 'network', 'network_view', 'device_description',
        'device_location', 'always_update_dns', 'options', 'comment'
    )
    'network'      = @(
        'network', 'comment', 'ipv4addr', 'netmask',
        'disable', 'members', 'extattrs'
    )
    'range'        = @(
        'network_view', 'comment', 'start_addr', 'end_addr',
        'network', 'member', 'disable', 'name',
        'extattrs'
    )
}

$Script:IpamAccessDetails = $null

#region Helper functions

Function Get-ErrorFromRestHC {
    Param (
        $Exception
    )

    $result = $Exception.Exception.Response.GetResponseStream()
    $reader = New-Object System.IO.StreamReader($result)
    $reader.BaseStream.Position = 0
    $reader.DiscardBufferedData()
    $Json = $reader.ReadToEnd() | ConvertFrom-Json

    if ($json.Text) {
        $json.Text
    }
    elseif ($json.Error) {
        $json.Error
    }
    else {
        $_
    }

    $Global:Error.RemoveAt(0)
}

Function Get-IpamAccessCookieHC {
    [OutputType([Microsoft.PowerShell.Commands.WebRequestSession])]
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory)]
        [String]$Uri,
        [Parameter(Mandatory)]
        [PSCredential]$Credential
    )

    Try {
        Write-Verbose 'Request authentication cookie'

        $Params = @{
            Uri                  = "$Uri/record:host?_return_as_object=1"
            Method               = 'GET'
            Credential           = $Credential
            SessionVariable      = 'AuthCookie'
            SkipCertificateCheck = $true
        }
        $null = Invoke-RestMethod @Params

        $AuthCookie
    }
    Catch [System.Net.WebException] {
        $M = Get-ErrorFromRestHC -Exception $_
        throw "Failed retrieving the IPAM access cookie, API error: $M"
    }
    Catch {
        throw "Failed retrieving the IPAM access cookie: $_"
    }
}

Function Get-IpamSecuritySettingHC {
    [OutputType([PSCustomObject])]
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory)]
        [String]$Uri,
        [Parameter(Mandatory)]
        [PSCredential]$Credential
    )

    Try {
        $Params = @{
            Method               = 'GET'
            ContentType          = 'application/json'
            SkipCertificateCheck = $true
            Credential           = $Credential
            Uri                  = "$Uri/grid/b25lLmNsdXN0ZXIkMA:Infoblox?_return_as_object=1&_return_fields%2B=security_setting"
        }
        (Invoke-RestMethod @Params).result.security_setting
    }
    Catch [System.Net.WebException] {
        $M = Get-ErrorFromRestHC -Exception $_
        throw "Failed retrieving the IPAM security settings, API error: $M"
    }
    Catch {
        throw "Failed retrieving the IPAM security settings: $_"
    }
}

Function Get-IpamAccessDetailsHC {
    <#
    .SYNOPSIS
        Retrieve IPAM access credentials.

    .DESCRIPTION
        Retrieve IPAM access credentials like the Uri and Credential object of the correct
        environment.

    .PARAMETER Environment
        The IPAM system that needs to be addressed.

        All available systems are defined in the hashtable '$Credentials' at the top of this
        module file. These credentials can be updated when required and will be reflected
        throughout all functions in the module.
        Ex. Test, Prod, ...
    #>

    [OutputType([HashTable])]
    [CmdletBinding()]
    Param ()
    DynamicParam {
        & $EnvironmentParameter
    }

    Process {
        Try {
            #region Create variables from the hashtable
            $Environment = $PSBoundParameters.Environment

            foreach ($P in $Credentials[$Environment].GetEnumerator()) {
                New-Variable -Name $P.Key -Value $P.Value -EA Stop
            }
            #endregion

            #region Test mandatory parameters
            $MandatoryParameters = @('SamAccountName', 'Password', 'Uri')

            foreach ($M in $MandatoryParameters) {
                $Var = Get-Variable -Name $M -EA Ignore

                if (-not $Var.Value -or $Var.Value -eq '') {
                    throw "The parameter '$M' can not be blank or omitted. Please provide this parameter with a proper value."
                }
            }
            #endregion

            #region Get cookie timeout and WebSession
            $Params = @{
                Uri        = $Uri
                Credential = Import-CredentialsHC -SamAccountName $SamAccountName -Password $Password
            }

            $SessionTimeout = (Get-IpamSecuritySettingHC @Params).session_timeout - 60

            $WebSession = Get-IpamAccessCookieHC @Params
            #endregion

            #region Return a hashtable with the result
            @{
                Environment = $Environment
                Uri         = $Uri
                WebSession  = $WebSession
                Expires     = (Get-Date).AddSeconds($SessionTimeout)
            }
            #endregion
        }
        Catch {
            throw "Failed retrieving IPAM access details: $_"
        }
    }
}
#endregion

#region Core functions
Function New-IpamObjectHC {
    <#
    .SYNOPSIS
        Add a new object to IPAM

    .DESCRIPTION
        Add a new object to IPAM. This can be useful for creating a new fixed
         address or address reservation, a new network, ... .

        By default the required IPAM services are restarted after applying
        changes to the system. This is a requirement for IPAM. In case more
        speed is required, this can be skipped during the function call but
        should then be run at the end of your script to restart the needed
        services all at once when all actions are done by invoking
        'Restart-IpamServiceHC'.

    .PARAMETER Type
        When no ReferenceObject is supplied the Type is required. A Type can be Network,
        FixedAddress, ... . When using the parameter Type the whole IPAM table is queried.

        This is useful when you want to retrieve all data or are looking for specific data
        by using a search criteria in the Filter parameter

    .PARAMETER Property
        The properties returned by the API.

    .PARAMETER NoServiceRestart
        Omitting this switch will restart the required IPAM services. This will take some time
        so if multiple actions are required it's best to user this switch on the New and Updated
        functions and run the command 'Restart-IpamServiceHC' after all actions are done. It
        will speed up things.

    .EXAMPLE
        Make an address reservation in IPAM for mac address '03:03:33:33:33:36'. When a machine is
        detected with this mac address on the network the fixed IP address '10.20.32.1'  will be
        assigned to it by the IPAM DHCP.

        New-IpamObjectHC -Body @{
            ipv4addr    = '10.20.32.1'
            mac         = '03:03:33:33:33:36'
        }  -Type FixedAddress

    .EXAMPLE
        Add the next free available IP address within a subnet as a fixed address.

        $Networks = Get-IpamNetworkHC
        $Subnet = $Networks.result | Where-Object comment -Match 'lustin'

        New-IpamObjectHC -Body @{
            ipv4addr    = "func:nextavailableip:$($Subnet.network)"
            mac         = '03:03:33:33:33:36'
        }  -Type FixedAddress

    .EXAMPLE
        Make a reservation for mac address '03:03:33:33:33:36'. When the machine comes online
        it will receive the IP address '10.20.32.1' and the DNS name will match ths hostname
        to 'PC1'.

        New-IpamObjectHC -Body @{
            ipv4addr      = '10.20.32.1'
            mac           = '03:03:33:33:33:36'
            name          = 'PC1'
            ddns_hostname = 'PC1'
            match_client  = 'MAC_ADDRESS'
            enable_ddns   = $true
            comment       = 'This is a test from PowerShell'
        }  -Type FixedAddress
    #>

    [OutputType([PSCustomObject[]])]
    [CmdLetBinding()]
    Param (
        [Parameter(Mandatory)]
        [ValidateSet('Network', 'FixedAddress')]
        [String]$Type,
        [Parameter(Mandatory, ValueFromPipeline)]
        [ValidateNotNullOrEmpty()]
        [PSObject[]]$Body,
        [ValidateNotNullOrEmpty()]
        [String[]]$Property,
        [Switch]$NoServiceRestart
    )
    DynamicParam {
        & $EnvironmentParameter
    }

    Begin {
        Try {
            $Environment = $PSBoundParameters.Environment

            #region Request access details
            if ((-not $IpamAccessDetails) -or
                ($IpamAccessDetails.expires -le (Get-Date)) -or
                ($IpamAccessDetails.Environment -ne $Environment)) {
                $Script:IpamAccessDetails = Get-IpamAccessDetailsHC -Environment $Environment
            }

            $Uri = $IpamAccessDetails.Uri
            $WebSession = $IpamAccessDetails.WebSession
            #endregion

            #region Set Type to lower case
            $Type = $Type.ToLower()
            #endregion

            #region Get default properties
            if (-not $Property) {
                $Property = $DefaultProperties[$Type]
            }

            if (-not $Property) {
                throw "No default properties defined for type '$Type'"
            }
            #endregion

            #region Test properties and create string
            $Property.Where( { $_ -match '\s' }).foreach( {
                    throw "The property '$_' cannot contain spaces."
                })

            $ReturnFieldString = ($Property -join ',').ToLower()
            #endregion

            #region Post params
            $PostParams = @{
                Method      = 'POST'
                ContentType = 'application/json'
                WebSession  = $WebSession
            }
            #endregion
        }
        Catch {
            throw "Failed adding a new IPAM object with type '$Type': $_"
        }
    }

    Process {
        $Result = foreach ($B in $Body) {
            Try {
                #region Test body type
                if (-not (
                        ($B -is [System.Collections.Hashtable]) -or
                        ($B -is [System.Management.Automation.PSCustomObject])
                    )) {
                    throw "The parameter 'Body' only supports type 'HashTable' or 'PSCustomObject'."
                }
                #endregion

                #region Convert Body to HashTable
                if ($B -is [System.Management.Automation.PSCustomObject]) {
                    $Hash = @{ }
                    foreach ($P in $B.PSObject.Properties) {
                        $Hash[$P.Name] = $P.Value
                    }

                    $B = $Hash
                }
                #endregion

                #region Convert Body properties to lower case
                foreach ($K in @($B.Keys)) {
                    $value = $B[$K]
                    $B.Remove($K)
                    $B[$K.ToLower()] = $value
                }
                #endregion

                #region Convert NULL values to empty string
                foreach ($K in @($B.Keys)) {
                    if ($null -eq $B[$K]) {
                        $B[$K] = ''
                    }
                }
                #endregion
            }
            Catch {
                throw "Failed adding a new IPAM object with type '$Type': $_"
            }

            Try {
                #region Add new IPAM object
                $Params = @{
                    Uri                  = "$Uri/$Type`?_return_fields%2B=$ReturnFieldString&_return_as_object=1"
                    # Body = @(
                    #     $B
                    # ) | ConvertTo-Json
                    SkipCertificateCheck = $true
                    Body                 = [System.Text.Encoding]::UTF8.GetBytes((@(
                                $B
                            ) | ConvertTo-Json))
                }
                Invoke-RestMethod @PostParams @Params
                #endregion
            }
            Catch [System.Net.WebException] {
                $M = Get-ErrorFromRestHC -Exception $_
                Write-Error "Failed adding a new IPAM object with type '$Type', API error: $M"
            }
            Catch {
                Write-Error "Failed adding a new IPAM object with type '$Type': $_"
            }
        }

        if (-not $NoServiceRestart) {
            Restart-IpamServiceHC -Environment $Environment
        }

        #region Return only unique records with all properties
        if ($Result) {
            @($Result.result | Group-Object '_ref').ForEach( {
                    $_.Group[0] }) | Select-Object -Property ($Property + '_ref')
        }
        #endregion
    }
}

Function Get-IpamObjectHC {
    <#
    .SYNOPSIS
        Retrieve objects from IPAM.

    .DESCRIPTION
        Retrieve different types of objects from IPAM. When no filter is used all objects are
        retrieved. Objects can be subnets (etwork), fixed IP addresses (fixedaddress), ...

        By uisng the filter only specific objects can be retrieved that match the search
        criteria.

    .PARAMETER ReferenceObject
        When no Type is supplied the ReferenceObject is required. The ReferenceObject is
        the '_ref' property found on a reply from a call to the API.

        This is usefull in case you want to query additional fields of an object which
        are not returend by default.

    .PARAMETER Type
        When no ReferenceObject is supplied the Type is required. A Type can be Network,
        FixedAddress, ... . When using the parameter Type the whole IPAM table is queried.

        This is usefull when you want to retrieve all data or are looking for specific data
        by using a search criteria in the Filter parameter

    .PARAMETER Property
        The properties returned by the API.

    .PARAMETER Filter
        This filter will be evaluated by the API and cannot contain spaces. Multiple filters
        are allowed and will be evaluated seperately. The filter is applied as 'xxx -OR xxx'
        and not 'xxx -AND xxx'.

        While searching for network objects, you can filter the data using regular expressions.
        You would need to specify the ~ modifier to indicate you are querying with a regular expression.

        - A search argument can use the following modifiers
        Modifier Explanation
        ! Negates the condition
        : Makes string matching case insensitive
        ~ Regular expression search. Expressions are unanchored
        < Less than or equal
        > Greater than or equal

        - Only one of the following can be specified at a time: greater than, less than, and
          regular expressions.
        - Depending on the attribute type, following are modifiers supported by extensible attributes:
            ▪ integer and date support !, < and >.
            ▪ All other types behave like strings and support !, ~ and :.
            • When you need to update or create multiple records, you can store the data

    .EXAMPLE
        Retrieve the network with subnetmask '10.22.122.0/24' by using the Filter.

        Get-IpamObjectHC -Type Network -Filter 'network=10.22.122.0/24'

    .EXAMPLE
        Retrieve all subnets and fixed addresses.

        Get-IpamObjectHC -Type Network
        Get-IpamObjectHC -Type FixedAddress

    .EXAMPLE
        Retrieve all fixed addresses that have mac address '0:21:b7:bd:1b:af' or network mask '10.22.52.0/24'

        Get-IpamObjectHC -Type FixedAddress -Property comment, network, mac -Filter 'mac=0:21:b7:bd:1b:af','network=10.22.52.0/24'

        _ref         : fixedaddress/ZG5zLmZpeGVkX2FkZHJlc3MkMTAuNjEuMjEwLjgxLjAuLg:10.61.210.81/default
        comment      : komi 4000p
        ipv4addr     : 10.61.210.81
        mac          : 00:21:b7:bd:1b:af
        network      : 10.61.0.0/16

        _ref         : fixedaddress/ZG5zLmZpeGVkX2FkZHJlc3MkMTAuMjIuNTIuNjAuMC4u:10.22.52.60/default
        comment      : KOMI 4000 P
        ipv4addr     : 10.22.52.60
        mac          : 00:21:b7:0d:d9:30
        network      : 10.22.52.0/24

        _ref         : fixedaddress/ZG5zLmZpeGVkX2FkZHJlc3MkMTAuMjIuNTIuNjEuMC4u:10.22.52.61/default
        comment      : Komi 4000 P
        ipv4addr     : 10.22.52.61
        mac          : 00:21:b7:f5:14:7f
        network      : 10.22.52.0/24

    .EXAMPLE
        Retrieve all fixed addresses from IPAM that contain the string 'komi' in the field 'comment'.
        The search is case insensitive.

        Get-IpamObjectHC -Type FixedAddress -Filter 'comment~:=KOMI' -Property comment

        _ref         : fixedaddress/ZG5zLmZpeGVkX2FkZHJlc3MkMTAuNTYuMjMuMjMzLjAuLg:10.56.23.233/default
        comment      : Komi 4402 Dummy Mac
        ipv4addr     : 10.56.23.233
        network_view : default

        _ref         : fixedaddress/ZG5zLmZpeGVkX2FkZHJlc3MkMTAuMjIuNjAuNjYuMC4u:10.22.60.66/default
        comment      : printer komi 4000
        ipv4addr     : 10.22.60.66
        network_view : default

        _ref         : fixedaddress/ZG5zLmZpeGVkX2FkZHJlc3MkMTAuMjIuNjAuNjUuMC4u:10.22.60.65/default
        comment      : KOMI 4000
        ipv4addr     : 10.22.60.65
        network_view : default

    .EXAMPLE
        Create a new fixed address and retrieve its properties by uisng the ReferenceObject.

        $FixedAddress = New-IpamObjectHC -Body @{
            ipv4addr = '10.20.32.1'
            mac      = '03:03:33:33:33:36'
        } -Type FixedAddress

        Get-IpamObjectHC -ReferenceObject $FixedAddress -Property mac,name,ddns_domainname,ddns_hostname,device_type,device_vendor,enable_ddns,extattrs,disable,network,network_view,device_description,device_location,always_update_dns,options,comment

    .LINK
        https://ipam
        https://ipam/wapidoc
        https://www.infoblox.com/wp-content/uploads/infoblox-deployment-infoblox-rest-api.pdf
    #>

    [OutputType([PSCustomObject[]])]
    [CmdLetBinding(DefaultParameterSetName = 'Type')]
    Param (
        [Parameter(Mandatory, ParameterSetName = 'Type')]
        [ValidateSet('FixedAddress', 'Network', 'Range')]
        [String]$Type,
        [Parameter(Mandatory, ValueFromPipeline, ParameterSetName = 'Ref')]
        [ValidateNotNullOrEmpty()]
        [Object[]]$ReferenceObject,
        [ValidateNotNullOrEmpty()]
        [String[]]$Property,
        [Parameter(ParameterSetName = 'Type')]
        [ValidateNotNullOrEmpty()]
        [String[]]$Filter
    )
    DynamicParam {
        & $EnvironmentParameter
    }

    Begin {
        Try {
            $Environment = $PSBoundParameters.Environment

            #region Request access details
            if ((-not $IpamAccessDetails) -or
                ($IpamAccessDetails.expires -le (Get-Date)) -or
                ($IpamAccessDetails.Environment -ne $Environment)) {
                $Script:IpamAccessDetails = Get-IpamAccessDetailsHC -Environment $Environment
            }

            $Uri = $IpamAccessDetails.Uri
            $WebSession = $IpamAccessDetails.WebSession
            #endregion

            #region Test Filter values
            $Filter.Where( { $_ -match '\s' }).ForEach( {
                    throw "The Filter '$_' cannot contain spaces."
                })
            #endregion

            #region Get parameters
            $GetParams = @{
                Method               = 'GET'
                WebSession           = $WebSession
                SkipCertificateCheck = $true
            }
            #endregion

            $Collection = @()
        }
        Catch {
            throw "Failed retrieving IPAM object for type '$Type': $_"
        }
    }

    Process {
        Try {
            #region Get Uri prefix and Type
            foreach ($R in $ReferenceObject) {
                if ($R -is [String]) {
                    $Ref = $R
                }
                else {
                    $Ref = $R._ref
                }

                #region Test ReferenceObject value
                if ($Ref -match '\s') {
                    throw "The ReferenceObject '$Ref' cannot contain spaces."
                }
                #endregion

                $Collection += @{
                    ID   = $Ref
                    Type = $Ref.Split('/', 2)[0]
                }
            }

            if (-not $ReferenceObject) {
                $Collection += @{
                    ID   = $Type.ToLower()
                    Type = $Type
                }
            }
            #endregion
        }
        Catch {
            throw "Failed retrieving IPAM object for '$Ref': $_"
        }
    }

    End {
        Try {
            $CollectionType = $Collection[0].Type

            #region Only one Type at the same time is supported
            $Collection.Type.where( { $_ -ne $CollectionType }).foreach( {
                    throw 'Only one object type per query is supported.'
                })
            #endregion

            #region Get default properties
            if (-not $Property) {
                Try {
                    $Property = $DefaultProperties[$CollectionType]
                }
                Catch {
                    throw "No default properties defined for object type '$CollectionType', please specify your own with the '-Property' parameter."
                }
            }
            #endregion

            #region Test properties and create string
            $Property.Where( { $_ -match '\s' }).foreach( {
                    throw "The property '$_' cannot contain spaces."
                })

            $ReturnFieldString = ($Property -join ',').ToLower()
            #endregion

            #region Create Uris
            foreach ($C in $Collection) {
                $C.Uri = @()

                $BaseUri = '{0}/{1}' -f $Uri, $C.ID

                foreach ($F in $Filter) {
                    $C.Filter = $F
                    $C.Uri += "$BaseUri`?{0}&_return_fields%2B={1}&_return_as_object=1" -f $F, $ReturnFieldString
                }

                if (-not $Filter) {
                    $C.Uri += "$BaseUri`?_return_fields%2B={0}&_return_as_object=1" -f $ReturnFieldString
                }

                if (-not $ReferenceObject) {
                    # Paging not supported for object reference
                    $C.Uri = $C.Uri.foreach( {
                            '{0}&_paging=1&_max_results=800' -f $_
                        })
                }
            }
            #endregion
        }
        Catch {
            throw "Failed retrieving IPAM object: $_"
        }

        $Result = foreach ($U in $Collection.Uri) {
            Try {
                #region Get object
                Write-Verbose "Get IPAM object '$U'"

                if ($PartialResult = Invoke-RestMethod @GetParams -Uri $U) {
                    $PartialResult.result

                    while ($PartialResult | Get-Member -Name 'next_page_id' -MemberType Properties) {
                        $PartialResult = Invoke-RestMethod @GetParams -Uri "$U&_page_id=$($PartialResult.next_page_id)"
                        $PartialResult.result
                    }
                }
                #endregion
            }
            Catch [System.Net.WebException] {
                $M = Get-ErrorFromRestHC -Exception $_
                Write-Error "Failed retrieving IPAM object '$U', API error: $M"
            }
            Catch {
                Write-Error "Failed retrieving IPAM object '$U'': $_"
            }
        }

        #region Return only unique records with all properties
        if ($Result) {
            @($Result | Group-Object '_ref').ForEach( {
                    $_.Group[0] }) | Select-Object -Property ($Property + '_ref')
        }
        #endregion
    }
}

Function Update-IpamObjectHC {
    <#
    .SYNOPSIS
        Update an IPAM object.

    .DESCRIPTION
        Set specific values in fields of an IPam object. This is usefull when you don't
        want to create a new object but simply want to change a field value. An object
        is returned representing the new values.

    .PARAMETER Type
        When no ReferenceObject is supplied the Type is required. A Type can be Network,
        FixedAddress, ... . When using the parameter Type the whole IPAM table is queried.

        This is useful when you want to retrieve all data or are looking for specific data
        by using a search criteria in the Filter parameter

    .PARAMETER Property
        The properties returned by the API.

    .PARAMETER NoServiceRestart
        Omitting this switch will restart the required IPAM services. This will
        ake some time so if multiple actions are required it's best to user
        this switch on the New and Updated
        functions and run the command 'Restart-IpamServiceHC' after all actions are done. It
        will speed up things.

    .EXAMPLE
        Set the comment field to 'Komi printer' for the object with fixed address '10.20.32.1',
        also update other fields in the process.

        $Obj = Get-IpamObjectHC -Type FixedAddress -Filter 'ipv4addr=10.20.32.1'

        Update-IpamObjectHC -ReferenceObject $Obj._ref -Body @{
            name          = 'Printer1'
            ddns_hostname = 'Printer1'
            comment       = 'Komi printer'
            mac           = '3:03:33:33:00:00'
            match_client  = 'MAC_ADDRESS'
            enable_ddns   = $true
        }

        _ref          : fixedaddress/ZG5zLmZpeGVkX2FkZHJlc3MkMTAuMjAuMzIuMS4wLi4:10.20.32.1/default
        name          : Printer1
        ddns_hostname : Printer1
        comment       : Komi printer
        enable_ddns   : True
        ipv4addr      : 10.20.32.1
        mac           : 03:03:33:33:00:00
        match_client  : MAC_ADDRESS
    #>

    [OutputType([PSCustomObject[]])]
    [CmdLetBinding()]
    Param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [ValidateNotNullOrEmpty()]
        [Object[]]$ReferenceObject,
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [PSObject]$Body,
        [ValidateNotNullOrEmpty()]
        [String[]]$ReturnField,
        [Switch]$NoServiceRestart
    )
    DynamicParam {
        & $EnvironmentParameter
    }

    Begin {
        Try {
            if (-not (
                    ($Body -is [System.Collections.Hashtable]) -or
                    ($Body -is [System.Management.Automation.PSCustomObject])
                )) {
                throw "The parameter 'Body' only supports type 'HashTable' or 'PSCustomObject'."
            }

            #region Convert Body to HashTable
            if ($Body -is [System.Management.Automation.PSCustomObject]) {
                $Hash = @{ }
                foreach ($P in $Body.PSObject.Properties) {
                    $Hash[$P.Name] = $P.Value
                }

                $Body = $Hash
            }
            #endregion

            #region Convert Body properties to lower case
            foreach ($K in @($Body.Keys)) {
                $value = $Body[$K]
                $Body.Remove($K)
                $Body[$K.ToLower()] = $value
            }
            #endregion

            $Environment = $PSBoundParameters.Environment

            #region Request access details
            if ((-not $IpamAccessDetails) -or
                ($IpamAccessDetails.expires -le (Get-Date)) -or
                ($IpamAccessDetails.Environment -ne $Environment)) {
                $Script:IpamAccessDetails = Get-IpamAccessDetailsHC -Environment $Environment
            }

            $Uri = $IpamAccessDetails.Uri
            $WebSession = $IpamAccessDetails.WebSession
            #endregion

            #region Test ReturnField values and create string
            if (-not $ReturnField) {
                $ReturnField = @($Body.Keys)
            }

            $ReturnField.Where( { $_ -match '\s' }).foreach( {
                    throw "The ReturnField '$_' cannot contain spaces."
                })

            $ReturnField = ($ReturnField -join ',').ToLower()
            #endregion

            #region Put parameters
            $PutParams = @{
                Method      = 'PUT'
                ContentType = 'application/json'
                WebSession  = $WebSession
            }
            #endregion

            $Collection = @{ }
        }
        Catch {
            throw "Failed updating IPAM object '$ReferenceObject': $_"
        }
    }

    Process {
        Try {
            foreach ($R in $ReferenceObject) {
                #region Get Uri ReferenceObject string
                if ($R -is [String]) {
                    $Ref = $R
                }
                else {
                    $Ref = $R._ref
                }
                #endregion

                #region Ignore duplicates
                if ($Collection.ContainsKey($Ref)) {
                    Continue
                }
                #endregion

                #region Test ReferenceObject value
                if ($Ref -match '\s') {
                    throw "The ReferenceObject '$Ref' cannot contain spaces."
                }
                #endregion

                #region Create Uri prefox and add ReturnField
                $Collection[$Ref] = if ($ReturnField) {
                    "$Uri/$Ref`?_return_fields%2B=$ReturnField"
                }
                else {
                    "$Uri/$Ref"
                }
                #endregion
            }
        }
        Catch {
            throw "Failed updating IPAM object '$ReferenceObject': $_"
        }
    }

    End {
        $Result = foreach ($U in $Collection.Values) {
            Try {
                #region Update object
                $Params = @{
                    Uri                  = "$U&_return_as_object=1"
                    Body                 = @(
                        $Body
                    ) | ConvertTo-Json
                    SkipCertificateCheck = $true
                }
                Invoke-RestMethod @PutParams @Params
                #endregion
            }
            Catch [System.Net.WebException] {
                $M = Get-ErrorFromRestHC -Exception $_
                throw "Failed updating IPAM object '$U', API error: $M"
            }
            Catch {
                throw "Failed updating IPAM object '$U': $_"
            }
        }

        if (-not $NoServiceRestart) {
            Restart-IpamServiceHC -Environment $Environment
        }

        if ($Result) {
            $Result.result
        }
    }
}

Function Remove-IpamObjectHC {
    <#
    .SYNOPSIS
        Remove an object from IPAM.

    .DESCRIPTION
        Remove an object from IPAM. When the object is no longer needed it can
        be removed by using its ReferenceObject string.

    .PARAMETER ReferenceObject
        The ReferenceObject is an IPAM object ID that  is unique for each IPAM
        object. To find the correct ReferenceObject string the function
        et-IpamObjectHC can be used.

    .PARAMETER Environment
        The IPAM system that needs to be addressed.

        All available systems are defined in the hashtable '$Credentials' at
        the top of this module file. These credentials can be updated when
        required and will be reflected throughout all functions in the module.
        Ex. Test, Prod, ...

    .EXAMPLE
        Remove the address reservation for IP '10.20.32.1'

        $Params = @{
            Environment = 'Test'
            Type        = 'FixedAddress'
            Filter      = "ipv4addr=10.20.32.1"
        }
        Get-IpamObjectHC @Params | Remove-IpamObjectHC @testParams

    .EXAMPLE
        Remove the network object with reference ID string 'network\xyz'

        Remove-IpamObjectHC -Environment 'Test' -ReferenceObject 'network\xyz'
    #>

    [CmdLetBinding()]
    Param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [ValidateNotNullOrEmpty()]
        [Object[]]$ReferenceObject,
        [Switch]$NoServiceRestart
    )
    DynamicParam {
        & $EnvironmentParameter
    }

    Begin {
        Try {
            $Environment = $PSBoundParameters.Environment

            #region Request access details
            if ((-not $IpamAccessDetails) -or
                ($IpamAccessDetails.expires -le (Get-Date)) -or
                ($IpamAccessDetails.Environment -ne $Environment)) {
                $Script:IpamAccessDetails = Get-IpamAccessDetailsHC -Environment $Environment
            }

            $Uri = $IpamAccessDetails.Uri
            $WebSession = $IpamAccessDetails.WebSession
            #endregion

            #region Remove parameters
            $RemoveParams = @{
                Method     = 'DELETE'
                WebSession = $WebSession
            }
            #endregion
        }
        Catch {
            throw "Failed removing IPAM object '$ReferenceObject': $_"
        }
    }

    Process {
        foreach ($R in $ReferenceObject) {
            Try {
                #region Get ReferenceObject string
                if (-not ($R -is [String])) {
                    $R = $R._ref
                }
                #endregion

                #region Test ReferenceObject
                if ($R -match '\s') {
                    throw "the ReferenceObject '$R' cannot contain spaces."
                }
                #endregion
            }
            Catch {
                throw "Failed removing IPAM object '$R': $_"
            }

            Try {
                #region Remove IPAM object
                $Params = @{
                    Uri                  = "$Uri/$($R)"
                    SkipCertificateCheck = $true
                }
                Invoke-RestMethod @RemoveParams @Params
                #endregion
            }
            Catch [System.Net.WebException] {
                $M = Get-ErrorFromRestHC -Exception $_
                Write-Error "Failed removing IPAM object '$R', API error: $M"
            }
            Catch {
                Write-Error "Failed removing IPAM object '$R': $_"
            }
        }
    }

    End {
        if (-not $NoServiceRestart) {
            Restart-IpamServiceHC -Environment $Environment
        }
    }
}

Function Restart-IpamServiceHC {
    <#
    .SYNOPSIS
        Restart the IPAM services.

    .DESCRIPTION
        In case changes have been requested through the API or the GUI within
        IPAM, for example adding a new fixed address, it can be required to
        restart the IPAM DNS or DHCP service.

        By default, this function only restarts the services that are required
        or requested to be restarted. In case the function is called and no
        restart is required in IPAM, nothing will happen. In case a forced
        restart of a service is required, the switch '-Force' needs to be
        provided.

    .PARAMETER Name
        Defines the service name which needs to be restarted. This can be the:
        - DNS  : Dynamic Name System service
        - DHCP : Dynamic Host Configuration Protocol  service
        - ALL  : Both of the above

    .PARAMETER Force
        When the switch '-Force' is used the specified service is forced to
        restart, even if it's not required by IPAM.

    .PARAMETER Environment
        The IPAM system that needs to be addressed.

        All available systems are defined in the hashtable '$Credentials' at
        the top of this module file. These credentials can be updated when
        required and will be reflected throughout all functions in the module.
        Ex. Test, Prod, ...

    .EXAMPLE
        Restart only those IPAM services that need to be restarted.

        Restart-IpamServiceHC

    .EXAMPLE
        Restart all IPAM services, regardless of their state.

        Restart-IpamServiceHC -Force

    .EXAMPLE
        Only restart the IPAM services 'DHCP', regardless of its state.

        Restart-IpamServiceHC -Name DHCP -Force
    #>

    [OutputType()]
    [CmdLetBinding()]
    Param (
        [ValidateSet('All', 'DNS', 'DHCP')]
        [ValidateNotNullOrEmpty()]
        [String]$Name = 'ALL',
        [Switch]$Force
    )
    DynamicParam {
        & $EnvironmentParameter
    }

    Process {
        Try {
            $Environment = $PSBoundParameters.Environment

            #region Request access details
            if ((-not $IpamAccessDetails) -or
                ($IpamAccessDetails.expires -le (Get-Date)) -or
                ($IpamAccessDetails.Environment -ne $Environment)) {
                $Script:IpamAccessDetails = Get-IpamAccessDetailsHC -Environment $Environment
            }

            $Uri = $IpamAccessDetails.Uri
            $WebSession = $IpamAccessDetails.WebSession
            #endregion

            #region Post parameters
            $PostParams = @{
                Method      = 'POST'
                ContentType = 'application/json'
                WebSession  = $WebSession
            }
            #endregion

            $Body = @{
                member_order   = 'SIMULTANEOUSLY'
                service_option = $Name
            }

            if ($Force) { $Body.restart_option = 'FORCE_RESTART' }

            $Params = @{
                Uri                  = "$Uri/grid/b25lLmNsdXN0ZXIkMA:Infoblox?_function=restartservices"
                Body                 = $Body | ConvertTo-Json
                SkipCertificateCheck = $true
            }

            $null = Invoke-RestMethod @PostParams @Params
        }
        Catch [System.Net.WebException] {
            $M = Get-ErrorFromRestHC -Exception $_
            throw "Failed restarting the IPAM service '$Name', API error: $M"
        }
        Catch {
            throw "Failed restarting the IPAM service '$Name': $_"
        }
    }
}
#endregion

#region Proxy functions
Function Get-IpamDhcpRangeHC {
    <#
    .SYNOPSIS
        Retrieve IPAM DHCP range objects.

    .DESCRIPTION
        Retrieve all IPAM DHCP ranges, found in IPAM under the header:
        Data Management > DHCP > Network > Range.

        By using the filter, only specific objects can be retrieved that match
        the search criteria.

    .PARAMETER Property
        The properties returned by the API.

    .PARAMETER Filter
        This filter will be evaluated by the API and cannot contain spaces.
        This means that the query will be faster, because the API filters for
        us.

        Multiple filters are allowed and will be evaluated separately. In case
        of multiple filters they are applied with the logical operator '-or'.
        When for example the following filter is used '-Filter A, B', results
        are returned in case condition A or condition B is met.

        While searching for objects, you can filter the data using regular
        expressions. You would need to specify the ~ modifier to indicate you
        are querying with a regular expression.

        - A search argument can use the following modifiers
        Modifier Explanation
        ! Negates the condition
        : Makes string matching case insensitive
        ~ Regular expression search. Expressions are unanchored
        < Less than or equal
        > Greater than or equal

        - Only one of the following can be specified at a time: greater than,
          less than, and
          regular expressions.
        - Depending on the attribute type, following are modifiers supported by
          extensible attributes:
            ▪ integer and date support !, < and >.
            ▪ All other types behave like strings and support !, ~ and :.
            • When you need to update or create multiple records,
              you can store the data

    .EXAMPLE
        Get-IpamDhcpRangeHC -Environment Test

        # Retrieve all ranges from the test environment with all their
        # properties.

        network_view : default
        comment      : Network Equipment
        start_addr   : 10.78.3.98
        end_addr     : 10.78.3.100
        network      : 10.78.3.96/28
        member       :
        disable      : False
        name         :
        extattrs     :
        _ref         : range/ZG5zLjEwMC8vLzAv:10.78.3.98/10.78.3.100/default

        network_view : default
        comment      : Standard DHCP Range for 28 Subnet
        start_addr   : 10.78.3.101
        end_addr     : 10.78.3.110
        network      : 10.78.3.96/28
        member       :
        disable      : False
        name         :
        extattrs     :
        _ref         : range/ZG5zLmRoTAvLy8wLw:10.78.3.101/10.78.3.110/default

    .LINK
        https://ipam
        https://ipam/wapidoc
        https://www.infoblox.com/wp-content/uploads/infoblox-deployment-infoblox-rest-api.pdf
    #>

    [OutputType([PSCustomObject[]])]
    [CmdletBinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [string[]]${Property},
        [ValidateNotNullOrEmpty()]
        [string[]]${Filter}
    )
    DynamicParam {
        & $EnvironmentParameter
    }

    Begin {
        Try {
            $outBuffer = $null
            if ($PSBoundParameters.TryGetValue('OutBuffer', [ref]$outBuffer)) {
                $PSBoundParameters['OutBuffer'] = 1
            }
            $wrappedCmd = $ExecutionContext.InvokeCommand.GetCommand('Get-IpamObjectHC',
                [System.Management.Automation.CommandTypes]::Function)

            $scriptCmd = { & $wrappedCmd @PSBoundParameters -Type 'Range' }
            $steppablePipeline = $scriptCmd.GetSteppablePipeline()
            $steppablePipeline.Begin($PSCmdlet)
        }
        Catch {
            throw
        }
    }

    Process {
        Try {
            $steppablePipeline.Process($_)
        }
        Catch {
            throw
        }
    }

    End {
        Try {
            $steppablePipeline.End()
        }
        Catch {
            throw
        }
    }
}

Function Get-IpamFixedAddressHC {
    <#
    .SYNOPSIS
        Retrieve IPAM fixed address objects.

    .DESCRIPTION
        Retrieve all IPAM fixed addresses, known in IPAM under the name
        FixedAddress.

        By using the filter, only specific objects can be retrieved that match
        the search criteria.

    .PARAMETER Property
        The properties returned by the API.

    .PARAMETER Filter
        This filter will be evaluated by the API and cannot contain spaces.
        This means that the query will be faster, because the API filters for
        us.

        Multiple filters are allowed and will be evaluated separately. In case
        of multiple filters they are applied with the logical operator '-or'.
        When for example the following filter is used '-Filter A, B', results
        are returned in case condition A or condition B is met.

        While searching for objects, you can filter the data using regular
        expressions. You would need to specify the ~ modifier to indicate you
        are querying with a regular expression.

        - A search argument can use the following modifiers
        Modifier Explanation
        ! Negates the condition
        : Makes string matching case insensitive
        ~ Regular expression search. Expressions are unanchored
        < Less than or equal
        > Greater than or equal

        - Only one of the following can be specified at a time: greater than,
        less than, and regular expressions.
        - Depending on the attribute type, following are modifiers supported by
        extensible attributes:
            ▪ integer and date support !, < and >.
            ▪ All other types behave like strings and support !, ~ and :.
            • When you need to update or create multiple records, you can store the data

    .EXAMPLE
        Get-IpamFixedAddressHC -Environment Test

        Retrieve all fixed addresses from the test environment with all their
        properties. This is the slowest search because the API needs to
        retrieve all properties for all fixed address objects. However,
        this will not have an impact on the IPAM server because of the use of
        'paging' in the background.

        mac                : 00:21:b7:9d:b0:71
        name               : PC!
        ipv4addr           : 10.62.2.84
        ddns_domainname    :
        ddns_hostname      : PC!
        device_type        :
        device_vendor      :
        enable_ddns        : True
        extattrs           :
        disable            : False
        network            : 10.62.0.0/16
        network_view       : default
        device_description :
        device_location    :
        always_update_dns  : False
        comment            :
        _ref               : fixedaddress/ZG5zLmZpNC4wLi4:10.62.2.84/default

    .EXAMPLE
        Get-IpamFixedAddressHC -Environment Test -Filter 'mac=00:20:6b:e2:19:9f' -Property mac, name, ipv4addr

        Retrieve the fixed address with mac address '00:20:6b:e2:19:9f' from
        the test environment

        mac      : 00:20:6b:e2:19:9f
        name     : PC1
        ipv4addr : 10.20.43.201
        _ref     : fixedaddressZHJlc3LjAuLg:10.20.43.201/default

    .EXAMPLE
        $AllFixedAddresses = Get-IpamFixedAddressHC -Environment Test
        $AllFixedAddresses | Where-Object ({ $_.Name -eq 'PC1' })

        Retrieve the fixed address with with name 'PC1'. To do this
        we first need to get all fixed addresses, because the property 'Name'
        is not a searchable field according to the API

    .EXAMPLE
        Get-IpamFixedAddressHC -Environment Test -Filter 'comment~:=Komi' -Property comment, network, ipv4addr

        # Retrieve all fixed addresses that have the text 'Komi' in their comment field. The search is
        # case insensitive.

        comment  : Printer
        network  : 10.22.136.0/24
        ipv4addr : 10.22.136.68
        _ref     : fixedaddress/ZG5zLmZpeGVkX2FkZHJlc3MkMTAuMjIuMTM2LjY4LjAuLg:10.22.136.68/default

    .EXAMPLE
        Get-IpamFixedAddressHC -Environment Test -Filter 'ipv4addr=10.57.70.152' -Property comment, network, ipv4addr

        Retrieve all fixed addresses with the IP address '10.57.70.152'

        comment  : Printer 1
        network  : 10.57.70.0/24
        ipv4addr : 10.57.70.152
        _ref     : fixedaddress/ZG5zLmZpeGVkX2FuLg:10.57.70.152/default

    .LINK
        https://ipam
        https://ipam/wapidoc
        https://www.infoblox.com/wp-content/uploads/infoblox-deployment-infoblox-rest-api.pdf
    #>

    [OutputType([PSCustomObject[]])]
    [CmdletBinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [string[]]${Property},
        [ValidateNotNullOrEmpty()]
        [string[]]${Filter}
    )
    DynamicParam {
        & $EnvironmentParameter
    }

    Begin {
        Try {
            $outBuffer = $null
            if ($PSBoundParameters.TryGetValue('OutBuffer', [ref]$outBuffer)) {
                $PSBoundParameters['OutBuffer'] = 1
            }
            $wrappedCmd = $ExecutionContext.InvokeCommand.GetCommand('Get-IpamObjectHC',
                [System.Management.Automation.CommandTypes]::Function)

            $scriptCmd = { & $wrappedCmd @PSBoundParameters -Type 'FixedAddress' }
            $steppablePipeline = $scriptCmd.GetSteppablePipeline()
            $steppablePipeline.Begin($PSCmdlet)
        }
        Catch {
            throw
        }
    }

    Process {
        Try {
            $steppablePipeline.Process($_)
        }
        Catch {
            throw
        }
    }

    End {
        Try {
            $steppablePipeline.End()
        }
        Catch {
            throw
        }
    }
}

Function Get-IpamNetworkHC {
    <#
    .SYNOPSIS
        Retrieve IPAM network objects.

    .DESCRIPTION
        Retrieve all IPAM subnets, known in IPAM under the name Network.

        By using the filter, only specific objects can be retrieved that match
        the search criteria.

    .PARAMETER Property
        The properties returned by the API.

    .PARAMETER Filter
        This filter will be evaluated by the API and cannot contain spaces.
        This means that the query will be faster, because the API filters for
        us.

        Multiple filters are allowed and will be evaluated separately. In case
        of multiple filters they are applied with the logical operator '-or'.
        When for example the following filter is used '-Filter A, B', results
        are returned in case condition A or condition B is met.

        While searching for objects, you can filter the data using regular
        expressions. You would need to specify the ~ modifier to indicate you
        are querying with a regular expression.

        - A search argument can use the following modifiers
        Modifier Explanation
        ! Negates the condition
        : Makes string matching case insensitive
        ~ Regular expression search. Expressions are unanchored
        < Less than or equal
        > Greater than or equal

        - Only one of the following can be specified at a time: greater than,
          less than, and regular expressions.
        - Depending on the attribute type, following are modifiers supported by
          extensible attributes:
            ▪ integer and date support !, < and >.
            ▪ All other types behave like strings and support !, ~ and :.
            • When you need to update or create multiple records, you can store the data

    .EXAMPLE
        Get-IpamNetworkHC -Environment Test

        Retrieve all subnets from the test environment with all their
        properties. This is the slowest search because the API needs to
        retrieve all properties for all network objects. However, this will not
        have an impact on the IPAM server because of the use of 'paging' in the
        background.

    .EXAMPLE
        Get-IpamNetworkHC -Environment Test -Filter 'network=10.22.122.0/24'

        Retrieve the network with subnetmask '10.22.122.0/24' from the test environment

    .EXAMPLE
        Get-IpamNetworkHC -Environment Test -Filter 'ipv4addr=10.20.61.0' -Property comment, network, ipv4addr

        Retrieve the network with ip address mask '10.20.61.0' from the test environment with only 3 properties

    .EXAMPLE
        Get-IpamNetworkHC -Environment Test -Filter 'comment~:=London' -Property comment, network

        Retrieve all networks that have the text 'London' in their comment
        field. The search is case insensitive.

    .EXAMPLE
        $Params = @{
            Environment = 'Test'
            Filter = 'network=10.78.253.32/27', 'network=10.57.62.0/24'
            Property = 'comment', 'network', 'ipv4addr'
        }
        Get-IpamNetworkHC @Params

        Retrieve all networks with the network subnetmask '10.78.253.32/27' or
        '10.57.62.0/24'

    .LINK
        https://ipam
        https://ipam/wapidoc
        https://www.infoblox.com/wp-content/uploads/infoblox-deployment-infoblox-rest-api.pdf
    #>

    [OutputType([PSCustomObject[]])]
    [CmdletBinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [string[]]${Property},
        [ValidateNotNullOrEmpty()]
        [string[]]${Filter}
    )
    DynamicParam {
        & $EnvironmentParameter
    }

    Begin {
        Try {
            $outBuffer = $null
            if ($PSBoundParameters.TryGetValue('OutBuffer', [ref]$outBuffer)) {
                $PSBoundParameters['OutBuffer'] = 1
            }
            $wrappedCmd = $ExecutionContext.InvokeCommand.GetCommand('Get-IpamObjectHC',
                [System.Management.Automation.CommandTypes]::Function)

            $scriptCmd = { & $wrappedCmd @PSBoundParameters -Type 'Network' }
            $steppablePipeline = $scriptCmd.GetSteppablePipeline()
            $steppablePipeline.Begin($PSCmdlet)
        }
        Catch {
            throw
        }
    }

    Process {
        Try {
            $steppablePipeline.Process($_)
        }
        Catch {
            throw
        }
    }

    End {
        Try {
            $steppablePipeline.End()
        }
        Catch {
            throw
        }
    }
}

Function New-IpamFixedAddressHC {
    <#
    .SYNOPSIS
        Add a new fixed address object to IPAM.

    .DESCRIPTION
        Add a new fixed address object to IPAM. This can be useful for address
        reservations
        based on mac address for example.

    .PARAMETER Property
        The properties returned by the API.

    .PARAMETER Body
        A hashtable containing key value pairs that are used to created the new
        fixed address.

    .PARAMETER NoServiceRestart
        Omitting this switch will restart the required IPAM services. This will
        take some time so if multiple actions are required it's best to user
        this switch on the New and Updated functions and run the command
        'Restart-IpamServiceHC' after all actions are done. It will speed up
        things.

    .EXAMPLE
        New-IpamFixedAddressHC -Environment Test -Body @{
            ipv4addr    = '10.20.32.145'
            mac         = '03:03:33:33:33:36'
        }

        Make an address reservation in IPAM for mac address
        '03:03:33:33:33:36'. When a machine is detected with this mac address
        on the network the fixed IP address '10.20.32.1'  will be assigned to
        it by the IPAM DHCP.

    .EXAMPLE
        $Subnet = Get-IpamNetworkHC -Environment Test -Filter 'comment~:=london' |
            Select-Object -First 1

        New-IpamFixedAddressHC -Environment Test -Body @{
            ipv4addr    = "func:nextavailableip:$($Subnet.network)"
            mac         = '03:03:33:33:33:36'
        }

        Add the next free available IP address within the subnet of 'london' as
        a fixed address.

    .EXAMPLE
        Make a reservation for mac address '03:03:33:33:33:36'. When the
        machine comes online it will receive the IP address '10.20.32.1' and
        the DNS name will match ths hostname to 'PC1'.

        New-IpamFixedAddressHC -Environment Test -Body @{
            ipv4addr          = '10.20.32.1'
            mac               = '03:03:33:33:33:36'
            name              = 'PC1'
            ddns_hostname     = 'PC1'
            match_client      = 'MAC_ADDRESS'
            enable_ddns       = $true
            always_update_dns = $true
            comment           = 'This is a test from PowerShell'
        } -Property ipv4addr, mac, name, ddns_hostname, match_client, enable_ddns, comment, network
    #>

    [OutputType([PSCustomObject[]])]
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [ValidateNotNullOrEmpty()]
        [PSObject[]]$Body,
        [ValidateNotNullOrEmpty()]
        [String[]]$Property,
        [Switch]$NoServiceRestart
    )
    DynamicParam {
        & $EnvironmentParameter
    }

    Begin {
        Try {
            $outBuffer = $null
            if ($PSBoundParameters.TryGetValue('OutBuffer', [ref]$outBuffer)) {
                $PSBoundParameters['OutBuffer'] = 1
            }
            $wrappedCmd = $ExecutionContext.InvokeCommand.GetCommand('New-IpamObjectHC',
                [System.Management.Automation.CommandTypes]::Function)

            $scriptCmd = { & $wrappedCmd @PSBoundParameters -Type 'FixedAddress' }
            $steppablePipeline = $scriptCmd.GetSteppablePipeline()
            $steppablePipeline.Begin($PSCmdlet)
        }
        Catch {
            throw
        }
    }

    Process {
        Try {
            $steppablePipeline.Process($_)
        }
        Catch {
            throw
        }
    }

    End {
        Try {
            $steppablePipeline.End()
        }
        Catch {
            throw
        }
    }
}

Function New-IpamNetworkHC {
    <#
    .SYNOPSIS
        Add a new network object to IPAM.

    .DESCRIPTION
        Add a new network object to IPAM.

    .PARAMETER Property
        The properties returned by the API.

    .PARAMETER Body
        A hashtable containing key value pairs that are used to created the new
        fixed address.

    .PARAMETER NoServiceRestart
        Omitting this switch will restart the required IPAM services. This will
        take some time so if multiple actions are required it's best to user
        this switch on the New and Updated functions and run the command
        'Restart-IpamServiceHC' after all actions are done. It will speed up
        things.

    .EXAMPLE
        New-IpamNetworkHC -Environment Test -Body @{
            network  = '10.78.3.96/28'
            comment  = 'Printer'
            ipv4addr = '10.78.3.96'
            netmask  = 28
        }

        Create a new network in IPAM for mac address '03:03:33:33:33:36'. When
        a machine is detected with this mac address on the network the fixed IP
        address '10.20.32.1'  will be assigned to it by the IPAM DHCP.
    #>

    [OutputType([PSCustomObject[]])]
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [ValidateNotNullOrEmpty()]
        [PSObject[]]$Body,
        [ValidateNotNullOrEmpty()]
        [String[]]$Property,
        [Switch]$NoServiceRestart
    )
    DynamicParam {
        & $EnvironmentParameter
    }

    Begin {
        Try {
            $outBuffer = $null
            if ($PSBoundParameters.TryGetValue('OutBuffer', [ref]$outBuffer)) {
                $PSBoundParameters['OutBuffer'] = 1
            }
            $wrappedCmd = $ExecutionContext.InvokeCommand.GetCommand('New-IpamObjectHC',
                [System.Management.Automation.CommandTypes]::Function)

            $scriptCmd = { & $wrappedCmd @PSBoundParameters -Type 'Network' }
            $steppablePipeline = $scriptCmd.GetSteppablePipeline()
            $steppablePipeline.Begin($PSCmdlet)
        }
        Catch {
            throw
        }
    }

    Process {
        Try {
            $steppablePipeline.Process($_)
        }
        Catch {
            throw
        }
    }

    End {
        Try {
            $steppablePipeline.End()
        }
        Catch {
            throw
        }
    }
}
#endregion