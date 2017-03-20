# DSC configuration for Pull Server and Compliance Server
# No this script has no certificate requirements as the traffic is unencrypted
# This script requires the xPSDesiredStateConfiguration. This can be downloaded from https://gallery.technet.microsoft.com/xPSDesiredStateConfiguratio-417dc71d

configuration ConfigurePullServer
{
    param 
    (
        [string[]]$NodeName = 'localhost'
    )

    Import-DSCResource -ModuleName xPSDesiredStateConfiguration

    Node $NodeName
    {

        WindowsFeature DSCServiceFeature
        {
            Ensure = "Present"
            Name   = "DSC-Service"                      
        }

        Script UnlockIISSection
        {
            SetScript = { 
                $appcmd = "$env:windir\system32\inetsrv\appcmd.exe" 
                & $appCmd unlock config -section:access
                & $appCmd unlock config -section:anonymousAuthentication
                & $appCmd unlock config -section:basicAuthentication
                & $appCmd unlock config -section:windowsAuthentication
            }
			#Dummy test script to force the set script to run.
            TestScript              = { return $false }
            GetScript               = { <# This must return a hash table #> }
            DependsOn               = "[WindowsFeature]DSCServiceFeature" 
        }


        xDscWebService PSDSCPullServer
        {
            Ensure                  = "Present"
            EndpointName            = "PSDSCPullServer"
            Port                    = 8080
            PhysicalPath            = "$env:SystemDrive\inetpub\wwwroot\PSDSCPullServer"
            CertificateThumbPrint   = "AllowUnencryptedTraffic"         
            ModulePath              = "$env:PROGRAMFILES\WindowsPowerShell\DscService\Modules"
            ConfigurationPath       = "$env:PROGRAMFILES\WindowsPowerShell\DscService\Configuration"            
            State                   = "Started"
            DependsOn               = "[Script]UnlockIISSection"                        
        }

        xDscWebService PSDSCComplianceServer
        {
            Ensure                  = "Present"
            EndpointName            = "PSDSCComplianceServer"
            Port                    = 9080
            PhysicalPath            = "$env:SystemDrive\inetpub\wwwroot\PSDSCComplianceServer"
            CertificateThumbPrint   = "AllowUnencryptedTraffic"
            State                   = "Started"
            IsComplianceServer      = $true
            DependsOn               = "[xDSCWebService]PSDSCPullServer"
        }

        Script UpdateWebConfig
        {
            SetScript = {            
                 $webConfig = 'c:\inetpub\wwwroot\PSDSCPullServer\Web.config'
                 $doc = (Get-Content $webConfig) -as [Xml]
                 $obj = $doc.configuration.appSettings.add | where {$_.Key -eq 'dbprovider'}
                 $obj.value = 'System.Data.OleDb'
                 $obj = $doc.configuration.appSettings.add | where {$_.Key -eq 'dbconnectionstr'}
                 $obj.value = 'Provider=Microsoft.Jet.OLEDB.4.0;Data Source=c:\Program Files\WindowsPowerShell\DscService\Devices.mdb;'
                 $doc.Save($webConfig)

				#update the web config for the complaince server
                $webConfig = 'c:\inetpub\wwwroot\PSDSCComplianceServer\Web.config'
                $doc = (Get-Content $webConfig) -as [Xml]
                $obj = $doc.configuration.appSettings.add | where {$_.Key -eq 'dbprovider'}
                $obj.value = 'System.Data.OleDb'
                $obj = $doc.configuration.appSettings.add | where {$_.Key -eq 'dbconnectionstr'}
                $obj.value = 'Provider=Microsoft.Jet.OLEDB.4.0;Data Source=c:\Program Files\WindowsPowerShell\DscService\Devices.mdb;'
                $modules = $doc.CreateElement('modules')
                $rm1 = $doc.CreateElement('remove')
                $rm1.SetAttribute('name','ServiceModel')
                $rm2 = $doc.CreateElement('remove')
                $rm2.SetAttribute('name','WebDAVModule')
                $rm3 = $doc.CreateElement('remove')
                $rm3.SetAttribute('name','AuthenticationModule')
                $rm4 = $doc.CreateElement('add')
                $rm4.SetAttribute('name','AuthenticationModule')
                $rm4.SetAttribute('type','Microsoft.Powershell.DesiredStateConfiguration.PullServer.AuthenticationPlugin, Microsoft.Powershell.DesiredStateConfiguration.Service')
                $webServerNode = $doc.SelectSingleNode("//configuration/system.webServer")
                $newNode = $webServerNode.AppendChild($modules)
                $newNode.AppendChild($rm1)
                $newNode.AppendChild($rm2)
                $newNode.AppendChild($rm3)
                $newNode.AppendChild($rm4)
                $obj = $webServerNode.security.authentication.anonymousAuthentication
                $obj.SetAttribute('enabled', 'true')
                $obj = $webServerNode.security.authentication.windowsAuthentication
                $obj.SetAttribute('enabled', 'false')
                $doc.Save($webConfig)
            }
			#Dummy test script to force the set script to run.
            TestScript              = { return $false }
            GetScript               = { <# This must return a hash table #> }
            DependsOn               = "[xDscWebService]PSDSCComplianceServer" 
        }
    }
 }

 
#ConfigurePullServer

#Start-DscConfiguration -Path .\ConfigurePullServer -Verbose -Wait -Force