using System;
using HermesBridge;
class AutoUpdatePolicyTests {
 static void Check(bool state,string why){if(!state)throw new Exception(why);}
 static int Main(){
  Check(AutoUpdatePolicy.CanUpdate(false,false,false,false,false),"Connected device cannot update");
  Check(!AutoUpdatePolicy.CanUpdate(false,false,true,false,false),"Interrupted enrollment");
  Check(!AutoUpdatePolicy.CanUpdate(false,false,false,true,false),"Interrupted revocation");
  Check(!AutoUpdatePolicy.CanUpdate(false,false,false,false,true),"Interrupted pending revoke");
  Check(!AutoUpdatePolicy.CanUpdate(true,false,false,false,false),"Update during shutdown");
  Check(AutoUpdatePolicy.ResumeAfterSwap(true,false),"Connected support not resumed");
  Check(AutoUpdatePolicy.ResumeAfterSwap(false,true),"Resident not resumed");
  Check(!AutoUpdatePolicy.ResumeAfterSwap(false,false),"Stopped support auto-connected unexpectedly");
  Console.WriteLine("PASS: auto-download while connected, safe deferral and explicit resume policy");
  return 0;
 }
}
