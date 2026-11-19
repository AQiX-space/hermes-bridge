using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Collections.Generic;
using System.Web.Script.Serialization;

namespace HermesBridge {
 // Runs as the SAME Windows logon token that launched Connector; does not log on
 // to Windows over sshd, create a service, request elevation or change ACLs.
 // Wire protocol: one newline-terminated JSON request on a LOOPBACK TCP socket.
 // Requests must carry a short-lived, anti-replay HMAC under the 256-bit broker
 // ticket. This tunnel is private to the approved Gate, never bound to LAN.
 public sealed class UserSessionAgent : IDisposable {
  public sealed class Request { public long ts {get;set;} public string nonce {get;set;} public string script {get;set;} public string mac {get;set;} }
  sealed class Result { public bool ok {get;set;} public string user {get;set;} public int exit_code {get;set;} public string stdout {get;set;} public string stderr {get;set;} public string error {get;set;} }
  readonly TcpListener listener;
  readonly byte[] key;
  readonly object gate=new object();
  readonly HashSet<string> used=new HashSet<string>(StringComparer.Ordinal);
  readonly JavaScriptSerializer json=new JavaScriptSerializer(){MaxJsonLength=128*1024};
  volatile bool closed=false;
  Process active;
  bool busy=false;
  public int Port {get;private set;}
  public string UserName {get;private set;}
  public UserSessionAgent(string brokerTicket){
   if(String.IsNullOrWhiteSpace(brokerTicket)||brokerTicket.Length<40)throw new InvalidDataException("Broker session ticket is missing");
   using(var sha=SHA256.Create())key=sha.ComputeHash(Encoding.UTF8.GetBytes("Hermes user-agent HMAC v1\n"+brokerTicket));
   using(var identity=WindowsIdentity.GetCurrent())UserName=identity.Name;
   listener=new TcpListener(IPAddress.Loopback,0);listener.Start(4);
   Port=((IPEndPoint)listener.LocalEndpoint).Port;
   ThreadPool.QueueUserWorkItem(_=>AcceptLoop());
  }
  static bool Equal(byte[] a,byte[] b){if(a==null||b==null||a.Length!=b.Length)return false;int diff=0;for(int i=0;i<a.Length;i++)diff|=a[i]^b[i];return diff==0;}
  static long UtcSeconds(){return (long)(DateTime.UtcNow-new DateTime(1970,1,1,0,0,0,DateTimeKind.Utc)).TotalSeconds;}
  bool Authenticate(Request r){
   if(r==null||String.IsNullOrEmpty(r.script)||r.script.Length>4096||r.nonce==null||r.nonce.Length!=32||r.mac==null||Math.Abs(UtcSeconds()-r.ts)>60)return false;
   foreach(char c in r.nonce)if(!Uri.IsHexDigit(c))return false;
   byte[] provided;
   try{provided=Convert.FromBase64String(r.mac);}catch{return false;}
   byte[] expected;
   using(var hmac=new HMACSHA256(key))expected=hmac.ComputeHash(Encoding.UTF8.GetBytes(r.ts+"\n"+r.nonce+"\n"+r.script));
   if(!Equal(provided,expected))return false;
   lock(gate){if(closed||used.Count>=10000||!used.Add(r.nonce))return false;return true;}
  }
  void AcceptLoop(){
   while(!closed){
    TcpClient client;
    try{client=listener.AcceptTcpClient();}catch(SocketException){break;}catch(ObjectDisposedException){break;}
    ThreadPool.QueueUserWorkItem(_=>Serve(client));
   }
  }
  void Serve(TcpClient client){
   using(client){
    try{
     client.ReceiveTimeout=5000;client.SendTimeout=6000;
     using(var stream=client.GetStream()){
      var bytes=new MemoryStream();int next=-1;
      while(bytes.Length<=16000&&(next=stream.ReadByte())>=0&&next!=10)bytes.WriteByte((byte)next);
      if(bytes.Length>16000||next!=10){Write(stream,new Result{ok=false,error="Invalid or oversized request"});return;}
      Request req;
      try{req=json.Deserialize<Request>(Encoding.UTF8.GetString(bytes.ToArray()));}
      catch{Write(stream,new Result{ok=false,error="Malformed request"});return;}
      if(!Authenticate(req)){Write(stream,new Result{ok=false,error="Unauthorized"});return;}
      lock(gate){if(closed||busy){Write(stream,new Result{ok=false,error="Agent busy or stopped"});return;}busy=true;}
      try{Write(stream,Run(req.script));}
      finally{lock(gate){busy=false;}}
     }
    }catch(IOException){}catch(ObjectDisposedException){}catch(Exception){}
   }
  }
  void Write(Stream stream,Result result){
   byte[] bytes=Encoding.UTF8.GetBytes(json.Serialize(result)+"\n");
   stream.Write(bytes,0,bytes.Length);stream.Flush();
  }
  static string Drain(StreamReader reader){
   var buffer=new char[2048];var sb=new StringBuilder();int size;
   while((size=reader.Read(buffer,0,buffer.Length))>0)if(sb.Length<32768)sb.Append(buffer,0,Math.Min(size,32768-sb.Length));
   return sb.ToString();
  }
  Result Run(string script){
   // Shell child inherits the exact user token (including elevation state) of the GUI.
   // Never supplies UserName/Password or uses runas/SYSTEM.
   string encoded=Convert.ToBase64String(Encoding.Unicode.GetBytes(script));
   var info=new ProcessStartInfo("powershell.exe","-NoLogo -NoProfile -NonInteractive -EncodedCommand "+encoded){
    UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true
   };
   using(var proc=new Process()){
    proc.StartInfo=info;
    try{
     // Start while holding the same lock as Dispose. A disconnect cannot
     // race between the closed-check and process creation.
     lock(gate){
      if(closed)return new Result{ok=false,error="Agent stopped"};
      proc.Start();active=proc;
     }
     Task<string> stdout=Task.Factory.StartNew(()=>Drain(proc.StandardOutput),TaskCreationOptions.LongRunning);
     Task<string> stderr=Task.Factory.StartNew(()=>Drain(proc.StandardError),TaskCreationOptions.LongRunning);
     bool exited=proc.WaitForExit(30000);
     if(!exited){try{proc.Kill();}catch{}proc.WaitForExit(2000);}
     Task.WaitAll(new Task[]{stdout,stderr},5000);
     if(!exited)return new Result{ok=false,error="Command timeout (30 seconds)",user=UserName,exit_code=-1};
     if(closed)return new Result{ok=false,error="Agent stopped",user=UserName,exit_code=-1};
     return new Result{ok=proc.ExitCode==0,user=UserName,exit_code=proc.ExitCode,stdout=stdout.IsCompleted?stdout.Result:"",stderr=stderr.IsCompleted?stderr.Result:""};
    }catch(Exception ex){return new Result{ok=false,user=UserName,error="Execution failed: "+ex.GetType().Name,exit_code=-1};}
    finally{lock(gate){if(ReferenceEquals(active,proc))active=null;}}
   }
  }
  public void Dispose(){
   lock(gate){if(closed)return;closed=true;
    if(active!=null)try{if(!active.HasExited)active.Kill();}catch{}
   }
   listener.Stop();Array.Clear(key,0,key.Length);
  }
 }
}
