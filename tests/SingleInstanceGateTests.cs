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
   using(var afterExit=new SingleInstanceGate(identity)){
    if(!afterExit.Acquired)throw new Exception("Lock not released on exit");
   }
   Console.WriteLine("PASS: one process per Windows SID across RDP sessions; independent users; lock released");return 0;
  }catch(Exception ex){Console.Error.WriteLine(ex);return 1;}
 }
}
