# ADSIOrgUnitAuditor
PS ADSI script to check ACEs of Organizational Units.    
This script searches for ACEs with GenericAll or CreateChild in the provided OU

> Version:    v1.2 (22.10.2024)

# How to use
If you want it to run in the current domain user context, just run it with:    
```powershell
.\Audit-ADSIOrganizationlUnit.ps1 -OUName <Name of OU to check>
```
If you want to run it against a target domain with provided credentials, specify the domain and DCIP, and you will be prompted for the domain credentials:    
```powershell
.\Audit-ADSIOrganizationlUnit.ps1 -OUName <Name of OU to check> -domain <domain.tld> -DCIP <DC-IP> -ExportasCSV <$true / $false>
```
If the parameter ExportasCSV is set to `$true`, a CSV file with the results will be exported to the current directory in the end.

# Example

```
.\Audit-ADSIOrganizationlUnit.ps1 -OUName NewUserOU -domain lab.local -DCIP 10.0.0.4 -ExportasCSV $true
[...]
[04:30] - INFO - Found 14 relevant ACEs in OU OU=NEWUSEROU,OU=LABUSERS,DC=lab,DC=local
Results:
[...]
OUIdentity          : S-1-5-32-548
OUACERight          : CreateChild, DeleteChild
OUInheritance       : False
OUObjType           : bf967aba-0de6-11d0-a285-00aa003049e2
OUOwner             : LAB\Domain Admins
OUDistinguishedName : OU=NEWUSEROU,OU=LABUSERS,DC=lab,DC=local

OUIdentity          : BUILTIN\Print Operators
OUACERight          : CreateChild, DeleteChild
OUInheritance       : False
OUObjType           : bf967aa8-0de6-11d0-a285-00aa003049e2
OUOwner             : LAB\Domain Admins
OUDistinguishedName : OU=NEWUSEROU,OU=LABUSERS,DC=lab,DC=local

OUIdentity          : LAB\usercreator
OUACERight          : CreateChild, DeleteChild, ListChildren, ReadProperty, GenericWrite
OUInheritance       : False
OUObjType           : 00000000-0000-0000-0000-000000000000
OUOwner             : LAB\Domain Admins
OUDistinguishedName : OU=NEWUSEROU,OU=LABUSERS,DC=lab,DC=local

OUIdentity          : LAB\usercreator
OUACERight          : CreateChild, DeleteChild
OUInheritance       : False
OUObjType           : bf967aba-0de6-11d0-a285-00aa003049e2
OUOwner             : LAB\Domain Admins
OUDistinguishedName : OU=NEWUSEROU,OU=LABUSERS,DC=lab,DC=local

OUIdentity          : LAB\usercreator
OUACERight          : CreateChild, DeleteChild
OUInheritance       : False
OUObjType           : 2628a46a-a6ad-4ae0-b854-2b12d9fe6f9e
OUOwner             : LAB\Domain Admins
OUDistinguishedName : OU=NEWUSEROU,OU=LABUSERS,DC=lab,DC=local

OUIdentity          : LAB\groupmanager
OUACERight          : CreateChild, DeleteChild
OUInheritance       : True
OUObjType           : bf967a9c-0de6-11d0-a285-00aa003049e2
OUOwner             : LAB\Domain Admins
OUDistinguishedName : OU=NEWUSEROU,OU=LABUSERS,DC=lab,DC=local

OUIdentity          : LAB\groupmanager
OUACERight          : GenericAll
OUInheritance       : True
OUObjType           : 00000000-0000-0000-0000-000000000000
OUOwner             : LAB\Domain Admins
OUDistinguishedName : OU=NEWUSEROU,OU=LABUSERS,DC=lab,DC=local
[...]
[04:30] - INFO - Results exported to C:\Users\rplant\22_10_2024-04_30_51-ADSIOrgUnitAuditor-Results.csv
```

# TODO
 - Add Parameter sets for better handling required parameters
 - Add parameters to further specify types of access control rights (other than GenericAll and CreateChilds)
 - Add python version? (Although, I dont like python that much...)
