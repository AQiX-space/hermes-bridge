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
   return "$ErrorActionPreference='Stop';"+
     "$c='"+capability+"';"+
     "$s=(Get-WindowsCapability -Online -Name $c).State;"+
     "if($s -ne 'Installed'){Add-WindowsCapability -Online -Name $c | Out-Host};"+
     "if((Get-WindowsCapability -Online -Name $c).State -ne 'Installed'){exit 9};exit 0";
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
