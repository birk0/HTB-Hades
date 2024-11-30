$json = Get-Content -Path "C:\Users\Administrator\AppData\Local\Windows\create.json" | ConvertFrom-Json
$Domain = $json.Domain
$Thumbprint = (Get-ChildItem "Cert:\LocalMachine\My\" | Where-Object { $_.Subject.Contains($json.Authority) }).Thumbprint
Import-Module "C:\Users\Administrator\AppData\Local\Windows\script_functions.ps1"
$DomainObjects = $json.Users + $json.Computers

$DomainACLs = @()

foreach($group in $json.Groups){
    foreach($acl in $group.ACL){
        $acl | Add-Member -MemberType NoteProperty -Name "Name" -Value $group.Name
        $DomainACLs+=$acl
    }
}

function Reset-Object {
    param($object, $target)

    $DN = $object.DistinguishedName
    $UAC = $object.userAccountControl -band -bnot 4194304
    $Clear = @("msDS-KeyCredentialLink")
    if(-not ($target.SPN)){
        $Clear+="servicePrincipalName"
    }
    Set-ADObject -Identity $DN -Replace @{"userAccountControl" = $UAC} -Clear $Clear
    if($target.ImportantPass){
        Set-ADAccountPassword -Identity $DN -Reset -NewPassword (ConvertTo-SecureString -AsPlainText $target.Pass -Force)
    }
    if($target.Path){
        $Path = (Get-ADOrganizationalUnit -Filter "name -eq '$($target.Path)'").DistinguishedName
        Move-ADObject -Identity $DN -TargetPath $Path
    }
}

function Reset-ObjectACLs {
    param($Object, $Target)

    if($target.Tamper){
        $DN = $object.DistinguishedName
        $Objects = (Get-ADObject -Filter * -SearchBase $DN).DistinguishedName
        foreach($obj in $Objects){
            $acl = Get-Acl -Path "AD:$obj"
            $ObjectName = (Get-ADObject -Identity $obj).Name
            foreach($ace in $acl.Access){
                $RID = ((New-Object System.Security.Principal.SecurityIdentifier($ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]))).Value -split "-")[-1]

                if([int]$RID -gt 1102){
                    $acl.RemoveAccessRule($ace) > $null
                }
            }
            foreach($rule in $DomainACLs){
                $IdentityReference = Get-ADObject -Filter "name -eq '$($rule.Path)'"
                if($IdentityReference.DistinguishedName -eq $obj){
                    $Sam = (Get-ADObject -Filter "name -eq '$($rule.Name)'" -Properties SamAccountName).SamAccountName
                    Set-NewACL -Rule $rule -Sam $Sam -Acl $acl
                }
            }
            foreach($JsonObj in $DomainObjects){
                if($ObjectName -eq $JsonObj.Name){
                    if($JsonObj.Protected){
                        Set-ADObject -Identity $obj -Replace @{"adminCount"="1"}
                        $acl.SetAccessRuleProtection($True, $False) # $True Disable Inheritance $False keep ACE as explicit
                    }
                    if($JsonObj.Disabled){
                        Disable-ADAccount -Identity $obj
                    }
                }
            }
            Set-Acl -Path "AD:$obj" -AclObject $acl
        }
    }
}

function Confirm-Object {
    param($Target)

    $object = Get-ADObject -Filter "name -eq '$($target.Name)'" -Properties *
    if($object){
        Reset-Object -Object $object -Target $target
        Reset-ObjectACLs -Object $object -Target $target
        return $True
    }
    return $False
}


foreach($user in $json.Users){
    if(-not(Confirm-Object -Target $user)){
        Add-NewUser -User $user -Path $json.UserPath.Path -Domain $Domain -Thumbprint $Thumbprint
    }
}

foreach($computer in $json.Computers){
    if(-not(Confirm-Object -Target $computer)){
        Add-NewComputer -Computer $computer -Path $json.ComputerPath.Path
    }
}

foreach($OU in $json.OUs){
    $object = Get-ADObject -Filter "name -eq '$($OU.Name)'" -Properties *
    Reset-ObjectACLs -Object $object -Target $OU
}

$Removelog = "C:\Users\ashley.b\Scripts\log.txt"
if(Test-Path $Removelog){
    Remove-Item $Removelog
}
