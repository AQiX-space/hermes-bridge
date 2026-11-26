using System;
using System.IO;
using System.Text;
using System.Net;
using System.Security.Cryptography;
using System.Diagnostics;
using System.Threading;

namespace HermesBridgeUpdater {
 internal static class Program {
  static byte[] Digest(string path) {using(SHA256 h=SHA256.Create())using(FileStream f=File.OpenRead(path))return h.ComputeHash(f);}
  static int ParseBeta(string value){int pos=value.LastIndexOf('.');int v;return pos>=0&&int.TryParse(value.Substring(pos+1),out v)?v:-1;}
  static int Main(string[] args) {
   // Separate helper: wait for parent; replace EXE without a shell; restore old binary on failure.
   if(args.Length!=5){Console.Error.WriteLine("args: PID source-new destination sha256 launch-flag");return 2;}
   if(args[4]!="launch"&&args[4]!="launch-resume"&&args[4]!="test-no-launch")return 2;
   int pid; if(!int.TryParse(args[0],out pid))return 2;
   string staged=Path.GetFullPath(args[1]),dest=Path.GetFullPath(args[2]),expected=args[3].ToLowerInvariant();
   if(expected.Length!=64||!System.Text.RegularExpressions.Regex.IsMatch(expected,"^[0-9a-f]{64}$"))return 2;
   if(!File.Exists(staged)||!File.Exists(dest)||!String.Equals(BitConverter.ToString(Digest(staged)).Replace("-","").ToLowerInvariant(),expected,StringComparison.Ordinal))return 3;
   // Allow renamed download files, but never replace an unrelated executable.
   if(!dest.EndsWith(".exe",StringComparison.OrdinalIgnoreCase))return 4;
   var info=FileVersionInfo.GetVersionInfo(dest);
   if(info.ProductName!="Hermes Connector"&&info.ProductName!="Гермес Мост")return 4;
   try {Process old=Process.GetProcessById(pid); if(!old.WaitForExit(30000))return 5;}catch(ArgumentException){}
   string backup=dest+".previous", tmp=dest+".pending";
   try {
    if(File.Exists(tmp))File.Delete(tmp);
    File.Copy(staged,tmp);
    if(!String.Equals(BitConverter.ToString(Digest(tmp)).Replace("-","").ToLowerInvariant(),expected,StringComparison.Ordinal))throw new Exception("hash mismatch after copy");
    if(File.Exists(backup))File.Delete(backup);
    File.Replace(tmp,dest,backup);
    if(args[4]=="launch"||args[4]=="launch-resume") {
     Process p=Process.Start(new ProcessStartInfo(dest,args[4]=="launch-resume"?"--resume-update":""){
      UseShellExecute=true});
     if(p==null)throw new Exception("launch failed");
     Thread.Sleep(2500);
     p.Refresh();
     if(p.HasExited)throw new Exception("new application terminated immediately");
    }
    return 0;
   }catch(Exception ex){
    bool restored=false;
    try{if(File.Exists(backup)){
     File.Copy(backup,dest,true);
     restored=true;
    }}catch(Exception restoreError){Console.Error.WriteLine("Restore failed: "+restoreError.Message);}
    if(restored&&args[4]=="launch-resume"){
     try{
      // Quarantine the exact crashing digest; do not loop on reinstall.
      string home=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"HermesBridge");
      Directory.CreateDirectory(home);
      File.WriteAllText(Path.Combine(home,"last-failed-auto-update.txt"),expected+"|"+DateTime.UtcNow.Ticks);
      string previous=FileVersionInfo.GetVersionInfo(dest).ProductVersion??"";
      bool canResume=previous.StartsWith("0.3.0-beta.")&&ParseBeta(previous)>=2;
      Process.Start(new ProcessStartInfo(dest,canResume?"--resume-update":""){
       UseShellExecute=true});
     }catch(Exception restartError){Console.Error.WriteLine("Rollback restart failed: "+restartError.Message);}
    }
    Console.Error.WriteLine(ex.Message);return 10;
   }finally {try {if(File.Exists(tmp))File.Delete(tmp);}catch{}}
  }
 }
}
