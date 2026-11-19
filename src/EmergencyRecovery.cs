using System;
using System.IO;
using System.Collections.Generic;
using System.Text;

namespace HermesBridge {
 // Never erase a remote grant merely because its Gate is unreachable.
 // Rotate away from the unusable old identity while preserving its key/ticket
 // for future authenticated revocation and forensic review.
 public static class EmergencyRecovery {
  public static string ArchiveAndRotate(string root,string targetGateway){
   if(targetGateway!="gr2" && targetGateway!="gr1")throw new InvalidOperationException("Unknown emergency gateway");
   string keys=Path.Combine(root,"keys"), history=Path.Combine(root,"recovery-archive");
   Directory.CreateDirectory(history);
   string archive=Path.Combine(history,DateTime.UtcNow.ToString("yyyyMMddTHHmmssfffZ")+"-"+Guid.NewGuid().ToString("N"));
   Directory.CreateDirectory(archive);
   var moved=new List<Tuple<string,string>>();
   try{
    foreach(string name in new[]{"client.ini","approval-ticket","approved-bridge.cfg","known_hosts","keys/device_ed25519","keys/device_ed25519.pub"}){
     string original=Path.Combine(root,name.Replace('/',Path.DirectorySeparatorChar));
     if(!File.Exists(original))continue;
     string dest=Path.Combine(archive,name.Replace('/',Path.DirectorySeparatorChar));
     Directory.CreateDirectory(Path.GetDirectoryName(dest));
     // Use moves within the same volume, so we can put everything back on failure.
     File.Move(original,dest);
     moved.Add(Tuple.Create(original,dest));
    }
    File.WriteAllText(Path.Combine(archive,"RECOVERY-NOTICE.txt"),
     "Prior Gate authorization is NOT confirmed revoked. Old key, DPAPI ticket and settings were preserved.\r\n"+
     "Do not restore the old SSH identity to an active Connector before revocation is verified.\r\n"+
     "New gateway: "+targetGateway+"; UTC: "+DateTime.UtcNow.ToString("o")+"\r\n",Encoding.UTF8);
    Directory.CreateDirectory(keys);
    return archive;
   }catch{
    for(int i=moved.Count-1;i>=0;i--){
     var entry=moved[i];
     try{if(File.Exists(entry.Item2)&&!File.Exists(entry.Item1))File.Move(entry.Item2,entry.Item1);}catch{}
    }
    throw;
   }
  }
 }
}
