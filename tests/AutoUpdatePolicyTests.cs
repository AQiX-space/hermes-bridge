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
  string digest=new string('a',64),other=new string('b',64);
  string record=digest+"|"+DateTime.UtcNow.AddMinutes(-2).Ticks;
  Check(AutoUpdatePolicy.IsQuarantined(digest,record,DateTime.UtcNow),"Crashing digest was not quarantined");
  Check(!AutoUpdatePolicy.IsQuarantined(other,record,DateTime.UtcNow),"New valid release incorrectly quarantined");
  Check(!AutoUpdatePolicy.IsQuarantined(digest,record,DateTime.UtcNow.AddDays(2)),"Expired quarantine never clears");
  Check(!AutoUpdatePolicy.IsQuarantined(digest,"malformed",DateTime.UtcNow),"Malformed quarantine accepted");
  Console.WriteLine("PASS: auto-download while connected, safe deferral and one-day failed-digest quarantine");
  return 0;
 }
}
