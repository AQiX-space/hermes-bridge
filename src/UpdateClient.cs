using System;
using System.Net;
using System.IO;
using System.Text;
using System.Security.Cryptography;
using System.Web.Script.Serialization;
using System.Diagnostics;
using System.Threading.Tasks;
using System.Text.RegularExpressions;
using System.Reflection;
namespace HermesBridge {
 public sealed class UpdateManifest {public string version{get;set;}public string url{get;set;}public string sha256{get;set;}public string signature{get;set;}}
 public static class UpdateClient {
  // Compiled-in RSA public key. Change only through a reviewed build; signer private key stays on DE2.
  public const string RsaPublicXml="<RSAKeyValue><Modulus>5FDNieHlD4GdzAKUYDAQ9+aP50S0RcA3GbPsUIN9+wRa9PvYNZTXt6j6HZAy6IZuysuoPDGZ4qzcaJfEMQTZM1maFyEd5SSbm/z1f/xsGfuOr5GHk2wJtr2Hrrw/jq5zbDXKWsAc+Xr+RopRQomud9OgEKRSvvJgLXRFFudqPszfGfnVyWUOsBOK31pIxDq9ivPSolxcTU6OUC+PVIDRsM2HBi3YFH7XnvtR/zFXSs1LZLYjbFc/lYJp++1RIyUO21GfvxGpaL/z91UmNWeDphxS44mO2Ra48HRRCfTB0Qs7TM5Ul7Zu1a0JpvDq9L91MiOo2xEigJ2yHF+FFO8oVdRHope2s2LwZqjQ0UtA73yJDbpJYcxxjxOeBCLxRyNYMmQxKr1Rh6MvGpQP1O1DNEV2IKDaR4FoLWPpkhxp0DsY1TSeR9iXyOUdenJSDWE0M7ou8/m33NnvbEgQ3P2X7pPW13aVBhizcRjS4mRem7clgVsvBCRf9qD6hPTAPsHr</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>";
  public const string ManifestUrl="https://updates.aqix.ru/hermes-bridge/stable.json";
  public static string CurrentVersion {get{return Assembly.GetExecutingAssembly().GetName().Version.ToString();}}
  public static bool Verify(UpdateManifest m) {
   if(m==null||m.version==null||m.url==null||m.sha256==null||m.signature==null)return false;
   Version v;Uri u;
   if(!Version.TryParse(m.version,out v)||!Uri.TryCreate(m.url,UriKind.Absolute,out u)||u.Scheme!="https")return false;
   if(!Regex.IsMatch(m.sha256,"^[a-f0-9]{64}$"))return false;
   if(u.Host!="updates.aqix.ru")return false;
   try{
    byte[] data=Encoding.UTF8.GetBytes(m.version+"\n"+m.url+"\n"+m.sha256);
    using(RSACryptoServiceProvider rsa=new RSACryptoServiceProvider()){
     rsa.PersistKeyInCsp=false;
     rsa.FromXmlString(RsaPublicXml);
     return rsa.VerifyData(data,CryptoConfig.MapNameToOID("SHA256"),Convert.FromBase64String(m.signature));
    }
   }catch{return false;}
  }
  public static async Task<UpdateManifest> CheckAsync(){
   return await Task.Run(()=>{
    ServicePointManager.SecurityProtocol|=SecurityProtocolType.Tls12;
    using(var wc=new WebClient()){
     wc.Headers[HttpRequestHeader.UserAgent]="HermesBridge/"+CurrentVersion;
     byte[] bytes=wc.DownloadData(ManifestUrl);
     if(bytes.Length>8192)throw new InvalidDataException("Manifest is too large");
     var m=new JavaScriptSerializer().Deserialize<UpdateManifest>(Encoding.UTF8.GetString(bytes));
     if(!Verify(m))throw new CryptographicException("Invalid update signature");
     Version latest=new Version(m.version),current=new Version(CurrentVersion);
     return latest>current?m:null;
    }
   });
  }
  public static async Task<string> StageAsync(UpdateManifest m,string dir){
   if(!Verify(m))throw new CryptographicException("Invalid update signature");
   return await Task.Run(()=>{
    Directory.CreateDirectory(dir);
    string path=Path.Combine(dir,"HermesBridge.new.exe");
    ServicePointManager.SecurityProtocol|=SecurityProtocolType.Tls12;
    using(var wc=new WebClient())wc.DownloadFile(m.url,path);
    FileInfo fi=new FileInfo(path);if(fi.Length>100*1024*1024||fi.Length<1024)throw new InvalidDataException("Unexpected binary size");
    using(var sha=SHA256.Create())using(var f=File.OpenRead(path)){
     string hash=BitConverter.ToString(sha.ComputeHash(f)).Replace("-","").ToLowerInvariant();
     if(hash!=m.sha256){File.Delete(path);throw new CryptographicException("Binary hash mismatch");}
    }
    return path;
   });
  }
  public static void Apply(UpdateManifest m,string staged){
   if(!Verify(m))throw new CryptographicException("Invalid update signature");
   string exe=Assembly.GetExecutingAssembly().Location;
   string helper=Path.Combine(Path.GetDirectoryName(exe),"HermesBridgeUpdater.exe");
   // The updater is embedded in the signed application build; no extra installation needed.
   using(Stream resource=Assembly.GetExecutingAssembly().GetManifestResourceStream("HermesBridgeUpdater.exe")){
    if(resource==null)throw new InvalidDataException("Updater resource absent");
    string temp=helper+".tmp";
    using(FileStream output=new FileStream(temp,FileMode.Create,FileAccess.Write,FileShare.None))resource.CopyTo(output);
    if(File.Exists(helper))File.Delete(helper);
    File.Move(temp,helper);
   }
   string cmd=Process.GetCurrentProcess().Id+" \""+staged+"\" \""+exe+"\" "+m.sha256+" launch";
   Process.Start(new ProcessStartInfo(helper,cmd){UseShellExecute=false,CreateNoWindow=true});
  }
 }
}
