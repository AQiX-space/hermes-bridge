using System;
using System.IO;
using System.Diagnostics;
using System.Reflection;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Web.Script.Serialization;

namespace HermesBridge {
 public static class GitHubUpdater {
  const string Repository="AQiX-space/hermes-bridge";
  // Personal private GitHub access: gh CLI uses the owner's credential store.
  // No GitHub token is embedded in the binary or passed on the command line.
  public sealed class Release {public string tagName{get;set;} public bool isDraft{get;set;} public Asset[] assets{get;set;}}
  public sealed class Asset {public string name{get;set;} public string digest{get;set;}}
  static string Run(string args, int timeoutMs=45000) {
   var pi=new ProcessStartInfo("gh.exe",args){UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true};
   using(var p=Process.Start(pi)){
    string output=p.StandardOutput.ReadToEnd();string err=p.StandardError.ReadToEnd();
    if(!p.WaitForExit(timeoutMs)){p.Kill();throw new TimeoutException("GitHub timeout");}
    if(p.ExitCode!=0)throw new InvalidOperationException("GitHub: "+err.Trim());
    return output;
   }
  }
  public static string CurrentTag {
   get {var a=Assembly.GetExecutingAssembly().GetCustomAttributes(typeof(AssemblyInformationalVersionAttribute),false);
    if(a.Length>0)return "v"+((AssemblyInformationalVersionAttribute)a[0]).InformationalVersion;
    return "v"+Assembly.GetExecutingAssembly().GetName().Version.ToString(); }
  }
  // Validates only canonical beta/stable version tags: no legacy hash-based tags.
  static Version VersionOf(string tag) {
   var m=Regex.Match(tag??"",@"^v(\d+)\.(\d+)\.(\d+)(?:-beta\.(\d+))?$");
   if(!m.Success)throw new InvalidDataException("Unexpected version tag");
   int beta=m.Groups[4].Success?int.Parse(m.Groups[4].Value):999999;
   return new Version(int.Parse(m.Groups[1].Value),int.Parse(m.Groups[2].Value),int.Parse(m.Groups[3].Value),beta);
  }
  public static async Task<Release> CheckAsync(){return await Task.Run(()=>{
   var json=Run("release list -R "+Repository+" --limit 100 --json tagName,isDraft",30000);
   var items=new JavaScriptSerializer().Deserialize<Release[]>(json);
   Version current=VersionOf(CurrentTag);string bestTag=null;Version best=current;
   foreach(var item in items){
    if(item.isDraft)continue;
    Version ver;try{ver=VersionOf(item.tagName);}catch{continue;}
    if(ver>best){best=ver;bestTag=item.tagName;}
   }
   if(bestTag==null)return null;
   var releaseJson=Run("release view "+bestTag+" -R "+Repository+" --json tagName,isDraft,assets");
   var r=new JavaScriptSerializer().Deserialize<Release>(releaseJson);
   if(r.isDraft||r.tagName!=bestTag||r.assets==null)throw new InvalidDataException("Invalid release metadata");
   return r;
  });}
  public static async Task<string> StageAsync(Release r,string dir){return await Task.Run(()=>{
   if(r==null||!Regex.IsMatch(r.tagName??"",@"^v\d+\.\d+\.\d+(?:-beta\.\d+)?$"))throw new InvalidDataException("Invalid release tag");
   var asset=Array.Find(r.assets,a=>a.name=="HermesBridge.exe");
   if(asset==null||!Regex.IsMatch(asset.digest??"","^sha256:[a-fA-F0-9]{64}$"))throw new InvalidDataException("Missing release digest");
   Directory.CreateDirectory(dir);
   Run("release download "+r.tagName+" -R "+Repository+" -p HermesBridge.exe -D \""+dir+"\" --clobber",120000);
   string path=Path.Combine(dir,"HermesBridge.exe");
   var info=new FileInfo(path);if(info.Length<1024||info.Length>100*1024*1024)throw new InvalidDataException("Invalid executable size");
   using(var f=File.OpenRead(path))using(var sha=SHA256.Create()){
    string digest=BitConverter.ToString(sha.ComputeHash(f)).Replace("-","").ToLowerInvariant();
    if("sha256:"+digest!=asset.digest.ToLowerInvariant()){File.Delete(path);throw new CryptographicException("GitHub release checksum mismatch");}
   }
   return path;
  });}
  public static void Apply(Release r,string path){
   // Apply still uses existing rollback-capable helper; SHA-256 is pinned to GitHub's returned release digest.
   var asset=Array.Find(r.assets,a=>a.name=="HermesBridge.exe");
   string sha=asset.digest.Substring("sha256:".Length).ToLowerInvariant();
   string exe=Assembly.GetExecutingAssembly().Location;
   string helper=Path.Combine(Path.GetDirectoryName(exe),"HermesBridgeUpdater.exe");
   using(var resource=Assembly.GetExecutingAssembly().GetManifestResourceStream("HermesBridgeUpdater.exe")){
    if(resource==null)throw new InvalidDataException("Missing embedded update helper");
    using(var output=File.Create(helper+".tmp"))resource.CopyTo(output);
    if(File.Exists(helper))File.Delete(helper);
    File.Move(helper+".tmp",helper);
   }
   string cmd=Process.GetCurrentProcess().Id+" \""+path+"\" \""+exe+"\" "+sha+" launch";
   Process.Start(new ProcessStartInfo(helper,cmd){UseShellExecute=false,CreateNoWindow=true});
  }
 }
}
