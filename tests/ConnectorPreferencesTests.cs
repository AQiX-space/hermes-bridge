using System;
using System.IO;
using HermesBridge;
class ConnectorPreferencesTests {
 static void Check(bool value,string message){if(!value)throw new Exception(message);}
 static int Main(){
  string path=Path.Combine(Path.GetTempPath(),"hermes-prefs-"+Guid.NewGuid().ToString("N"),"ui-preferences.ini");
  try{
   var defaults=ConnectorPreferences.Load(path);
   Check(defaults.Mode==ConnectorMode.Support&&!defaults.AutoDisconnect,"Default should not time out");
   defaults.AutoDisconnect=true;defaults.DisconnectMinutes=10;defaults.Save(path);
   var support=ConnectorPreferences.Load(path);
   Check(support.Mode==ConnectorMode.Support&&support.AutoDisconnect&&support.DisconnectMinutes==10,"Support preferences not persisted");
   Check(support.ShouldTimeOut(DateTime.UtcNow.AddMinutes(-11),DateTime.UtcNow),"Support timeout ignored");
   support.Mode=ConnectorMode.Resident;support.Save(path);
   var resident=ConnectorPreferences.Load(path);
   Check(resident.Mode==ConnectorMode.Resident&&!resident.AutoDisconnect,"Resident auto-disconnect remained enabled");
   Check(!resident.ShouldTimeOut(DateTime.UtcNow.AddYears(-1),DateTime.UtcNow),"Resident timed out on idle");
   Check(OpenSshComponents.Capability(SshComponent.Client)=="OpenSSH.Client~~~~0.0.1.0","Invalid client capability");
   Check(OpenSshComponents.Capability(SshComponent.Server)=="OpenSSH.Server~~~~0.0.1.0","Invalid server capability");
   var installServer=OpenSshComponents.Script(SshComponent.Server);
   Check(!installServer.Contains("Start-Service"),"Installing server must not start sshd");
   Check(installServer.Contains("Disable-NetFirewallRule"),"New inbound SSH rule remains enabled");
   Check(installServer.Contains("-not $previousRule"),"Existing firewall rule could be altered");
   Check(installServer.Contains("-not $previousService"),"Existing SSH daemon could be altered");
   Check(installServer.Contains("Stop-Service")&&installServer.Contains("StartupType Manual"),"Unexpected auto-start of a newly installed SSH daemon");
   Check(!OpenSshComponents.Script(SshComponent.Client).Contains("Disable-NetFirewallRule"),"Client-only installation must not touch inbound firewall");
   Console.WriteLine("PASS: support/resident persistence, idle timeout, native OpenSSH capability installation");return 0;
  }catch(Exception ex){Console.Error.WriteLine(ex);return 1;}
  finally{try{Directory.Delete(Path.GetDirectoryName(path),true);}catch{}}
 }
}
