using System;
using System.IO;
using System.Reflection;
[assembly: AssemblyInformationalVersion("0.2.0-beta.6")]
class Integration {
 static int Main(){
  try {
   var update=HermesBridge.GitHubUpdater.CheckAsync().GetAwaiter().GetResult();
   if(update==null||update.tag_name!="v0.2.0-beta.7")throw new Exception("Could not discover beta.7");
   Console.WriteLine("PASS: discovered "+update.tag_name+" without login");
   string dir=Path.Combine(Path.GetTempPath(),"Hermes-public-updater-test-"+Guid.NewGuid().ToString("N"));
   try {string path=HermesBridge.GitHubUpdater.StageAsync(update,dir).GetAwaiter().GetResult();
    if(!File.Exists(path))throw new Exception("binary not staged");
    Console.WriteLine("PASS: direct asset download and SHA256: "+new FileInfo(path).Length+" bytes");
   }finally{if(Directory.Exists(dir))Directory.Delete(dir,true);}
   return 0;
  }catch(Exception ex){Console.Error.WriteLine(ex);return 1;}
 }
}
