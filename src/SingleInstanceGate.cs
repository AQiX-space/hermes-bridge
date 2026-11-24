using System;
using System.Security.Principal;
using System.Threading;
namespace HermesBridge {
 // One Connector per Windows account, including manual and --resident launches.
 // Distinct users on one machine retain independent identities and processes.
 public sealed class SingleInstanceGate : IDisposable {
  Mutex mutex;
  public bool Acquired { get; private set; }
  // The Global kernel namespace spans local console and Remote Desktop sessions.
  // A Local mutex would allow two tunnels for the same SID across RDP logons.
  public static string NameForIdentity(string identity){
   if(String.IsNullOrWhiteSpace(identity))throw new ArgumentException("Missing Windows user SID");
   foreach(char ch in identity)if(!Char.IsLetterOrDigit(ch) && ch!='-')throw new ArgumentException("Invalid Windows user SID");
   return @"Global\HermesConnector-"+identity;
  }
  public SingleInstanceGate(string identity){
   bool created=false;
   mutex=new Mutex(true,NameForIdentity(identity),out created);
   Acquired=created;
  }
  public void Dispose(){
   if(mutex==null)return;
   if(Acquired)try{mutex.ReleaseMutex();}catch(ApplicationException){}
   mutex.Dispose();mutex=null;Acquired=false;
  }
 }
}
