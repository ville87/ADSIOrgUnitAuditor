# ADSIOrgUnitAuditor
PS ADSI script to check ACEs of Organizational Units.    
This script searches for ACEs with GenericAll or CreateChild in the provided OU

> Author:     Ville Koch (@vegvisir87, https://github.com/ville87)
  Version:    v1.0 (18.10.2024)

# Work in Progress
Currently it does not seem to work if you specify a target domain...

# TODO
 - Add Parameter sets for better handling required parameters
 - Add parameters to further specify types of access control rights (other than GenericAll and CreateChilds)