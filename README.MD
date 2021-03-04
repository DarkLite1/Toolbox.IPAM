# Description

A PowerShell module designed to easily interact with the IPAM REST API from InfoBlox. It provides CmdLet's for the most common CRUD operations like `New-IpamObjectHC`, `Get-IpamObjectHC`, `Remove-IpamObjectHC`, `Update-IpamObjectHC`, `Get-IpamDhcpRangeHC`, `Get-IpamNetworkHC`,  ... .

# Examples

## Get IPAM network details

Retrieve the network with subnetmask '10.22.122.0/24' from the environment 'Test'

```powershell
 Get-IpamNetworkHC -Environment 'Test' -Filter 'network=10.22.122.0/24'
```

Returns something like:

```
network  : 10.22.122.0/24
comment  : London
ipv4addr : 10.22.122.0
netmask  : 24
disable  : False
members  : {}
_ref     : network/ZG5zLm5ldHdvcmA:10.22.122.0/24/default
```

## Create a fixed address reservation

Make a fixed address reservation for ipv4addr '10.20.32.4' when the 'mac' address is still unknown. The API will set the 'mac' address to  '00:00:00:00:00:00' by default.

```powershell
New-IpamFixedAddressHC -Environment 'Test' -Body @{
    ipv4addr     = '10.20.32.4'
    match_client = 'RESERVED'
}
```

### Get DHCP ranges

Returns all DHCP ranges from the environment 'Prod' with all properties.

```powershell
Get-IpamDhcpRangeHC -Environment 'Prod'
```

# Installation

## Setup guide

1. Clone the repository into the folder `Toolbox.IPAM`
2. Rename `Passwords-example.json` to `Passwords.json` and update the file with your environment details
3. Optionally move the module folder to one of your module folders defined in `$env:PSModulePath`

## Using the module

- Run in any script `Import-Module $modulePath` and use the CmdLet's
  (only needed when the module is not in your default module folder `$env:PSModulePath`)
- List all available CmdLet's `Get-Command -Module Toolbox.IPAM`
- Read the help `Get-Help Get-IpamDhcpRangeHC`
- See the examples `Get-Help Get-IpamDhcpRangeHC -Examples`

# Running tests

Make sure your `Passwords.json` file contains an environment named 'Test' with the correct details.

```powershell
Install-Module -Name 'Pester'
Invoke-Pester $myPesterTestFile -Output 'Detailed'
```