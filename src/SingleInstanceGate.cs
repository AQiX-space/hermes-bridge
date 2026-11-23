using System;
using System.Security.Principal;
using System.Threading;
namespace HermesBridge {
 // One Connector per Windows account, including manual and --resident launches.
 // Distinct users on one machine retain independent identities and processes.
 public sealed class SingleInstanceGate : IDisposable {
  Mutex mutex;
  public bool Acquired { get; private set; }
  public SingleInstanceGate(string identity){
   if(String.IsNullOrWhiteSpace(identity))throw new ArgumentException("Missing Windows user SID");
   foreach(char ch in identity)if(!Char.IsLetterOrDigit(ch) && ch!='-')throw new ArgumentException("Invalid Windows user SID");
   bool created=false;
   mutex=new Mutex(true,@"Local\HermesConnector-"+identity,out created);
   Acquired=created;
  }
  public void Dispose(){
   if(mutex==null)return;
   if(Acquired)try{mutex.ReleaseMutex();}catch(ApplicationException){}
   mutex.Dispose();mutex=null;Acquired=false;
  }
 }
}
