using System;
using System.IO;
using System.Diagnostics;
using System.Threading.Tasks;
namespace HermesBridge {
 public enum SshComponent { Client, Server }
 public static class OpenSshComponents {
  public static string Capability(SshComponent component){
   return component==SshComponent.Client?"OpenSSH.Client~~~~0.0.1.0":"OpenSSH.Server~~~~0.0.1.0";
  }
  public static string Script(SshComponent component){
   string capability=Capability(component);
   if(component==SshComponent.Client){
    return "$ErrorActionPreference='Stop';"+
      "$c='"+capability+"';"+
      "if((Get-WindowsCapability -Online -Name $c).State -ne 'Installed'){Add-WindowsCapability -Online -Name $c | Out-Host};"+
      "if((Get-WindowsCapability -Online -Name $c).State -ne 'Installed'){exit 9};exit 0";
   }
   // Microsoft documents that the OpenSSH Server optional feature can create
   // an ENABLED inbound port-22 firewall rule. A helper installer must never
   // leave the freshly installed daemon reachable just because setup did so.
   // Previously existing rules/services belong to the machine administrator.
   return "$ErrorActionPreference='Stop';"+
     "$c='"+capability+"';"+
     "$wasInstalled=(Get-WindowsCapability -Online -Name $c).State -eq 'Installed';"+
     "$previousRule=Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue;"+
     "$previousService=Get-Service -Name 'sshd' -ErrorAction SilentlyContinue;"+
     "if(-not $wasInstalled){Add-WindowsCapability -Online -Name $c | Out-Host};"+
     "if((Get-WindowsCapability -Online -Name $c).State -ne 'Installed'){exit 9};"+
     "if(-not $wasInstalled){"+
       "if(-not $previousRule){"+
         "$rule=Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue;"+
         "if($rule){Disable-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction Stop;"+
           "if((Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction Stop).Enabled -ne 'False'){throw 'New SSH firewall rule is still enabled'}};"+
       "};"+
       "if(-not $previousService){"+
         "$service=Get-Service -Name 'sshd' -ErrorAction SilentlyContinue;"+
         "if($service){if($service.Status -eq 'Running'){Stop-Service -Name 'sshd' -ErrorAction Stop};"+
            "Set-Service -Name 'sshd' -StartupType Manual -ErrorAction Stop}"+
       "};"+
     "};exit 0";
  }
  public static async Task<int> InstallAsync(SshComponent component){
   if(!SshServerHealth.SupportsWindowsCapability())throw new NotSupportedException("Windows OpenSSH capability unavailable");
   string encoded=Convert.ToBase64String(System.Text.Encoding.Unicode.GetBytes(Script(component)));
   var info=new ProcessStartInfo("powershell.exe","-NoProfile -NonInteractive -EncodedCommand "+encoded){UseShellExecute=true,Verb="runas"};
   using(Process process=Process.Start(info)){
    if(process==null)throw new IOException("Unable to start Windows feature installer");
    await Task.Run(()=>process.WaitForExit());return process.ExitCode;
   }
  }
 }
}
