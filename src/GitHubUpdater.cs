using System;
using System.IO;
using System.Diagnostics;
using System.Net;
using System.Reflection;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Web.Script.Serialization;

namespace HermesBridge {
 public static class GitHubUpdater {
  const string Api="https://api.github.com/repos/AQiX-space/hermes-bridge/releases?per_page=100";
  // Public GitHub Releases: no token, gh CLI, mirror or backend needed.
  public sealed class Release {
   public string tag_name{get;set;}
   public bool draft{get;set;}
   public bool prerelease{get;set;}
   public Asset[] assets{get;set;}
   public string tagName {get{return tag_name;}}
  }
  public sealed class Asset {
   public string name{get;set;}
   public string digest{get;set;}
   public string browser_download_url{get;set;}
  }
  static WebClient Client() {
   ServicePointManager.SecurityProtocol |= SecurityProtocolType.Tls12;
   var c=new WebClient();c.Headers[HttpRequestHeader.UserAgent]="HermesConnector/"+CurrentTag;
   c.Headers[HttpRequestHeader.Accept]="application/vnd.github+json";
   return c;
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
   string json;
   using(var client=Client())json=client.DownloadString(Api);
   var releases=new JavaScriptSerializer().Deserialize<Release[]>(json);
   Version current=VersionOf(CurrentTag);Release best=null;Version bestVersion=current;
   foreach(var r in releases){
    if(r.draft)continue;
    Version v;try{v=VersionOf(r.tag_name);}catch{continue;}
    if(v>bestVersion){best=r;bestVersion=v;}
   }
   return best;
  });}
  public static async Task<string> StageAsync(Release r,string dir){return await Task.Run(()=>{
   if(r==null||r.draft||!Regex.IsMatch(r.tag_name??"",@"^v\d+\.\d+\.\d+(?:-beta\.\d+)?$"))throw new InvalidDataException("Invalid release tag");
   var asset=Array.Find(r.assets,a=>a.name=="HermesBridge.exe");
   if(asset==null||!Regex.IsMatch(asset.digest??"","^sha256:[a-fA-F0-9]{64}$"))throw new InvalidDataException("Release SHA256 unavailable");
   Uri u;if(!Uri.TryCreate(asset.browser_download_url,UriKind.Absolute,out u)||u.Scheme!="https"||u.Host!="github.com"||!u.AbsolutePath.StartsWith("/AQiX-space/hermes-bridge/releases/download/"))throw new InvalidDataException("Untrusted download URL");
   Directory.CreateDirectory(dir);
   string path=Path.Combine(dir,"HermesBridge.new.exe");
   using(var client=Client())client.DownloadFile(u,path);
   var info=new FileInfo(path);if(info.Length<1024||info.Length>100*1024*1024)throw new InvalidDataException("Invalid executable size");
   using(var f=File.OpenRead(path))using(var sha=SHA256.Create()){
    string digest=BitConverter.ToString(sha.ComputeHash(f)).Replace("-","").ToLowerInvariant();
    if("sha256:"+digest!=asset.digest.ToLowerInvariant()){File.Delete(path);throw new CryptographicException("GitHub checksum mismatch");}
   }
   return path;
  });}
  public static void Apply(Release r,string path){
   // Apply still uses existing rollback-capable helper; SHA-256 is pinned to GitHub's returned release digest.
   var asset=Array.Find(r.assets,a=>a.name=="HermesBridge.exe");
   string sha=asset.digest.Substring("sha256:".Length).ToLowerInvariant();
   string exe=Assembly.GetExecutingAssembly().Location;
   // Updater helper always lives in the per-user writable application directory.
   // A legacy EXE can be run from C:\ or another read-only directory.
   string home=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"HermesBridge");
   Directory.CreateDirectory(home);
   string helper=Path.Combine(home,"HermesBridgeUpdater.exe");
   string destination=exe;
   bool canReplace=true;
   string probe=Path.Combine(Path.GetDirectoryName(exe),".hermes-update-write-test-"+Guid.NewGuid().ToString("N"));
   try{using(FileStream f=File.Create(probe)){} File.Delete(probe);}
   catch(UnauthorizedAccessException){canReplace=false;}
   catch(IOException){canReplace=false;}
   finally{try{if(File.Exists(probe))File.Delete(probe);}catch{}}
   if(!canReplace){
    destination=Path.Combine(home,"HermesConnector.exe");
    if(!String.Equals(exe,destination,StringComparison.OrdinalIgnoreCase))File.Copy(exe,destination,true);
   }
   using(var resource=Assembly.GetExecutingAssembly().GetManifestResourceStream("HermesBridgeUpdater.exe")){
    if(resource==null)throw new InvalidDataException("Missing embedded update helper");
    string temporary=helper+".tmp";
    using(var output=File.Create(temporary))resource.CopyTo(output);
    if(File.Exists(helper))File.Delete(helper);
    File.Move(temporary,helper);
   }
   string cmd=Process.GetCurrentProcess().Id+" \""+path+"\" \""+destination+"\" "+sha+" launch";
   Process.Start(new ProcessStartInfo(helper,cmd){UseShellExecute=false,CreateNoWindow=true});
  }
 }
}
