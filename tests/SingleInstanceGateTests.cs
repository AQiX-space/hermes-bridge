using System;
using HermesBridge;
class SingleInstanceGateTests {
 static int Main(){
  try{
   string identity="TEST-"+Guid.NewGuid().ToString("N");
   if(!SingleInstanceGate.NameForIdentity(identity).StartsWith(@"Global\HermesConnector-",StringComparison.Ordinal))
    throw new Exception("Named mutex is not global across RDP sessions");
   using(var first=new SingleInstanceGate(identity)){
    if(!first.Acquired)throw new Exception("First instance should acquire lock");
    using(var second=new SingleInstanceGate(identity)){
     if(second.Acquired)throw new Exception("Second instance unexpectedly acquired same identity lock");
    }
    using(var differentUser=new SingleInstanceGate(identity+"-other")){
     if(!differentUser.Acquired)throw new Exception("Different Windows identity is blocked");
    }
   }
   bool acquiredByHandoff=false;
   using(var previous=new SingleInstanceGate(identity)){
    if(!previous.Acquired)throw new Exception("Cannot reserve lock for UAC handoff");
    var thread=new System.Threading.Thread(()=>{
     using(var raised=new SingleInstanceGate(identity,true)){
      acquiredByHandoff=raised.Acquired;
     }
    });
    thread.Start();
    System.Threading.Thread.Sleep(120);
    if(acquiredByHandoff)throw new Exception("New instance acquired lock before prior instance closed");
    previous.Dispose();
    if(!thread.Join(2200))throw new Exception("UAC instance did not recover mutex after previous process closed");
   }
   if(!acquiredByHandoff)throw new Exception("UAC handoff failed to take over after close");
   using(var afterExit=new SingleInstanceGate(identity)){
    if(!afterExit.Acquired)throw new Exception("Lock not released on exit");
   }
   Console.WriteLine("PASS: one process per Windows SID across RDP sessions; independent users; lock released");return 0;
  }catch(Exception ex){Console.Error.WriteLine(ex);return 1;}
 }
}
