using System;
using System.IO;
using HermesBridge;
class EmergencyRecoveryTests {
 static int Main(){
  string root=Path.Combine(Path.GetTempPath(),"hermes-recovery-test-"+Guid.NewGuid().ToString("N"));
  try{
   Directory.CreateDirectory(Path.Combine(root,"keys"));
   File.WriteAllText(Path.Combine(root,"approval-ticket"),"dpapi:encrypted-placeholder");
   File.WriteAllText(Path.Combine(root,"keys","device_ed25519"),"PRIVATE-OLD-KEY");
   File.WriteAllText(Path.Combine(root,"keys","device_ed25519.pub"),"OLD-PUBLIC-KEY");
   File.WriteAllText(Path.Combine(root,"client.ini"),"host=de2.nod.aqixnet.com\nslot=23000");
   File.WriteAllText(Path.Combine(root,"known_hosts"),"OLD-HOST-KEY");
   bool rejected=false;try{EmergencyRecovery.ArchiveAndRotate(root,"untrusted");}catch(InvalidOperationException){rejected=true;}
   if(!rejected||!File.Exists(Path.Combine(root,"approval-ticket")))throw new Exception("Invalid target affected state");
   string archive=EmergencyRecovery.ArchiveAndRotate(root,"gr2");
   foreach(var item in new[]{"approval-ticket","keys/device_ed25519","keys/device_ed25519.pub","known_hosts","client.ini"}){
    string original=Path.Combine(root,item.Replace('/',Path.DirectorySeparatorChar));
    string historic=Path.Combine(archive,item.Replace('/',Path.DirectorySeparatorChar));
    if(File.Exists(original)||!File.Exists(historic))throw new Exception("State not archived: "+item);
   }
   if(File.ReadAllText(Path.Combine(archive,"keys","device_ed25519"))!="PRIVATE-OLD-KEY")throw new Exception("Old identity destroyed");
   if(!File.ReadAllText(Path.Combine(archive,"RECOVERY-NOTICE.txt")).Contains("NOT confirmed revoked"))throw new Exception("Missing revoke warning");
   Console.WriteLine("PASS: offline Gate recovery archives old SSH identity, ticket, and config; invalid target refused");return 0;
  }catch(Exception ex){Console.Error.WriteLine(ex);return 1;}
  finally{if(Directory.Exists(root))Directory.Delete(root,true);}
 }
}
