using System;
using System.IO;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using System.Security.Cryptography;
using System.Threading.Tasks;
using System.Web.Script.Serialization;

namespace HermesBridge {
 public class EnrollmentTicket {public string ticket{get;set;}public string status{get;set;}public string code{get;set;}}
 public class EnrollmentResult {public string status{get;set;}public EnrollmentConfig config{get;set;}}
 public class EnrollmentConfig {public string host{get;set;}public int port{get;set;}public int slot{get;set;}public string hostkey{get;set;}}
 public static class EnrollmentClient {
  static readonly JavaScriptSerializer Parser=new JavaScriptSerializer();
  public static bool Valid(EnrollmentConfig c) {
   if(c==null||c.host==null||!Regex.IsMatch(c.host,@"^[a-zA-Z0-9.-]{3,255}$")||c.port<1||c.port>65535||c.slot<1024||c.slot>65535)return false;
   if(c.hostkey==null||!Regex.IsMatch(c.hostkey,@"^ssh-ed25519 [a-zA-Z0-9+/]+={0,2}$"))return false;
   try {byte[] blob=Convert.FromBase64String(c.hostkey.Substring(12));byte[] prefix={0,0,0,11,115,115,104,45,101,100,50,53,53,49,57,0,0,0,32};
    if(blob.Length!=51)return false;for(int i=0;i<prefix.Length;i++)if(blob[i]!=prefix[i])return false;return true;}
   catch{return false;}
  }
  static void CheckEndpoint(Uri u){if(u==null||u.Scheme!="https"||u.UserInfo.Length>0||u.Fragment.Length>0)throw new InvalidDataException("Enrollment requires HTTPS");}
  public static bool ShouldRenewPending(string status){return status=="expired";}
  // Diagnostics only. Prefer an active adapter with IPv4 default gateway;
  // never treat the reported address as a verified authorization identity.
  public static string LocalIPv4(){
   try {
    string fallback=null;
    foreach(var nic in NetworkInterface.GetAllNetworkInterfaces()){
     if(nic.OperationalStatus!=OperationalStatus.Up||nic.NetworkInterfaceType==NetworkInterfaceType.Loopback||nic.NetworkInterfaceType==NetworkInterfaceType.Tunnel)continue;
     var props=nic.GetIPProperties();
     bool gateway=false;
     foreach(var entry in props.GatewayAddresses)if(entry.Address.AddressFamily==AddressFamily.InterNetwork&&!IPAddress.IsLoopback(entry.Address)){gateway=true;break;}
     foreach(var address in props.UnicastAddresses){
      var ip=address.Address;
      if(ip.AddressFamily!=AddressFamily.InterNetwork||IPAddress.IsLoopback(ip))continue;
      byte[] bytes=ip.GetAddressBytes();
      if(bytes[0]==169&&bytes[1]==254)continue; // APIPA is not routable.
      if(gateway)return ip.ToString();
      if(fallback==null)fallback=ip.ToString();
     }
    }
    return fallback;
   }catch{return null;}
  }
  public static async Task<EnrollmentTicket> SubmitAsync(Uri endpoint,string device,string publicKey){
   CheckEndpoint(endpoint);
   if(!Regex.IsMatch(device??"",@"^[a-zA-Z0-9._-]{1,64}$"))throw new InvalidDataException("Bad device name");
   return await Task.Run(()=>{
    ServicePointManager.SecurityProtocol|=SecurityProtocolType.Tls12;
    var req=(HttpWebRequest)WebRequest.Create(new Uri(endpoint,"/v1/enroll"));req.Method="POST";req.ContentType="application/json";req.Timeout=15000;
    var payload=Encoding.UTF8.GetBytes(Parser.Serialize(new{device=device,public_key=publicKey.Trim(),computer_name=Environment.MachineName,local_ipv4=LocalIPv4()}));
    if(payload.Length>4096)throw new InvalidDataException("Public key request too long");
    using(var st=req.GetRequestStream())st.Write(payload,0,payload.Length);
    using(var res=(HttpWebResponse)req.GetResponse())using(var reader=new StreamReader(res.GetResponseStream())){
     var r=Parser.Deserialize<EnrollmentTicket>(reader.ReadToEnd());
     if(res.StatusCode!=HttpStatusCode.Accepted||r==null||r.status!="pending"||!Regex.IsMatch(r.ticket??"",@"^[a-zA-Z0-9_-]{40,60}$")||!Regex.IsMatch(r.code??"",@"^(?:[A-Z][a-z][0-9]{2}|[A-HJ-NP-Z2-9]{5})$"))throw new InvalidDataException("Enrollment response invalid");
     return r;
    }
   });
  }
  public static async Task<EnrollmentResult> PollAsync(Uri endpoint,string ticket){
   CheckEndpoint(endpoint);if(!Regex.IsMatch(ticket??"",@"^[a-zA-Z0-9_-]{40,60}$"))throw new InvalidDataException("Bad ticket");
   return await Task.Run(()=>{
    ServicePointManager.SecurityProtocol|=SecurityProtocolType.Tls12;
    var req=(HttpWebRequest)WebRequest.Create(new Uri(endpoint,"/v1/enroll/"+ticket));req.Timeout=15000;
    using(var response=(HttpWebResponse)req.GetResponse())using(var reader=new StreamReader(response.GetResponseStream())){
     var result=Parser.Deserialize<EnrollmentResult>(reader.ReadToEnd());
     if(result==null||result.status==null)throw new InvalidDataException("Invalid enrollment response");
     if(result.status=="approved"&&!Valid(result.config))throw new CryptographicException("Invalid approved gateway host key");
     return result;
    }
   });
  }
  // DPAPI: bearer ticket readable only in this Windows user's security context.
  // Legacy plaintext tickets are accepted only for one-time migration.
  public static void SaveTicket(string path,string ticket){
   if(!Regex.IsMatch(ticket??"",@"^[a-zA-Z0-9_-]{40,60}$"))throw new InvalidDataException("Invalid approval ticket");
   byte[] encrypted=ProtectedData.Protect(Encoding.ASCII.GetBytes(ticket),null,DataProtectionScope.CurrentUser);
   string temporary=path+"."+Guid.NewGuid().ToString("N")+".tmp";
   try{File.WriteAllText(temporary,"dpapi:"+Convert.ToBase64String(encrypted),Encoding.ASCII);
    if(File.Exists(path))File.Replace(temporary,path,null);else File.Move(temporary,path);
   }finally{if(File.Exists(temporary))File.Delete(temporary);}
  }
  public static string LoadTicket(string path){
   string stored=File.ReadAllText(path,Encoding.ASCII).Trim();
   if(stored.StartsWith("dpapi:",StringComparison.Ordinal)){
    var value=Encoding.ASCII.GetString(ProtectedData.Unprotect(Convert.FromBase64String(stored.Substring(6)),null,DataProtectionScope.CurrentUser));
    if(!Regex.IsMatch(value,@"^[a-zA-Z0-9_-]{40,60}$"))throw new InvalidDataException("Invalid decrypted ticket");
    return value;
   }
   if(!Regex.IsMatch(stored,@"^[a-zA-Z0-9_-]{40,60}$"))throw new InvalidDataException("Invalid legacy ticket");
   SaveTicket(path,stored);
   return stored;
  }
  public static async Task<bool> RevokeAsync(Uri endpoint,string ticket){
   CheckEndpoint(endpoint);if(!Regex.IsMatch(ticket??"",@"^[a-zA-Z0-9_-]{40,60}$"))throw new InvalidDataException("Bad revoke ticket");
   return await Task.Run(()=>{
    ServicePointManager.SecurityProtocol|=SecurityProtocolType.Tls12;
    var req=(HttpWebRequest)WebRequest.Create(new Uri(endpoint,"/v1/enroll/revoke"));req.Method="POST";req.ContentType="application/json";req.Timeout=15000;
    var payload=Encoding.UTF8.GetBytes(Parser.Serialize(new{ticket=ticket}));
    using(var st=req.GetRequestStream())st.Write(payload,0,payload.Length);
    using(var res=(HttpWebResponse)req.GetResponse())using(var reader=new StreamReader(res.GetResponseStream())){
     var result=Parser.Deserialize<EnrollmentResult>(reader.ReadToEnd());
     return res.StatusCode==HttpStatusCode.OK&&result!=null&&result.status=="revoked";
    }
   });
  }
  public static void SaveApproved(EnrollmentConfig config,string settingsDir){
   if(!Valid(config))throw new InvalidDataException("Untrusted enrollment configuration");
   Directory.CreateDirectory(settingsDir);
   string pin="["+config.host+"]:"+config.port+" "+config.hostkey+Environment.NewLine;
   string known=Path.Combine(settingsDir,"known_hosts");
   string pending=known+".new";File.WriteAllText(pending,pin,Encoding.ASCII);if(File.Exists(known))File.Delete(known);File.Move(pending,known);
   string cfg="host="+config.host+"\nport="+config.port+"\nslot="+config.slot+"\n";
   File.WriteAllText(Path.Combine(settingsDir,"approved-bridge.cfg"),cfg,Encoding.UTF8);
  }
 }

 // Each enrollment belongs to exactly one broker; never switch an active ticket
 // to another domain just because a transport is unavailable.
 public static class GatewayEndpoints {
  public const string Primary="https://gr1.touch01.top:18512/";
  public const string Backup="https://gr2.touch01.top:18512/";
  public const string Legacy="https://de2.nod.aqixnet.com:18512/";
  public static Uri Stored(string stored,string host){
   if(stored==Primary||stored==Backup||stored==Legacy)return new Uri(stored);
   if(String.Equals(host,"gr2.touch01.top",StringComparison.OrdinalIgnoreCase))return new Uri(Backup);
   if(String.Equals(host,"gr1.touch01.top",StringComparison.OrdinalIgnoreCase))return new Uri(Primary);
   if(String.Equals(host,"de2.nod.aqixnet.com",StringComparison.OrdinalIgnoreCase))return new Uri(Legacy);
   return new Uri(Primary);
  }
  public static async Task<Uri> ChooseAsync(string mode,Func<Uri,Task<bool>> probe=null){
   if(mode=="gr1")return new Uri(Primary);
   if(mode=="gr2")return new Uri(Backup);
   if(mode!="auto")throw new InvalidDataException("Invalid gateway mode");
   if(probe==null)probe=ProbeAsync;
   foreach(string url in new[]{Primary,Backup}){
    Uri target=new Uri(url);
    try{if(await probe(target))return target;}catch(WebException){}
   }
   throw new WebException("Both Hermes gateways are unavailable (GR1, GR2)");
  }
  // Check the *upstream broker*, not a static nginx /healthz, and the actual
  // SSH Gate banner. A successful ping or HTTPS proxy alone is insufficient.
  public static async Task<bool> ProbeAsync(Uri gateway){
   return await Task.Run(()=>{
    try{
     ServicePointManager.SecurityProtocol|=SecurityProtocolType.Tls12;
     var req=(HttpWebRequest)WebRequest.Create(new Uri(gateway,"/v1/enroll/hermes-unregistered-probe"));
     req.Method="GET";req.Timeout=3500;req.ReadWriteTimeout=3500;
     try{using(var res=(HttpWebResponse)req.GetResponse()){return false;}}
     catch(WebException ex){
      using(var response=ex.Response as HttpWebResponse){
       if(response==null||response.StatusCode!=HttpStatusCode.NotFound)return false;
      }
     }
     using(var tcp=new TcpClient()){
      var pending=tcp.BeginConnect(gateway.Host,22471,null,null);
      try{if(!pending.AsyncWaitHandle.WaitOne(2500))return false;
       tcp.EndConnect(pending);
      }finally{pending.AsyncWaitHandle.Close();}
      var stream=tcp.GetStream();stream.ReadTimeout=2500;
      byte[] banner=new byte[32];int n=stream.Read(banner,0,banner.Length);
      return n>=7&&Encoding.ASCII.GetString(banner,0,n).StartsWith("SSH-2.0",StringComparison.Ordinal);
     }
    }catch(Exception ex){
     if(ex is WebException||ex is SocketException||ex is IOException||ex is InvalidOperationException)return false;
     return false;
    }
   });
  }
 }
}
