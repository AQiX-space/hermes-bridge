using System;
using HermesBridge;
class ElevationSupportTests {
 static void Check(bool test,string msg){if(!test)throw new Exception(msg);}
 static int Main(){
  try{
   Check(ElevationSupport.CanElevateSameUser(false,TokenElevationKind.Limited),"UAC admin consent unavailable");
   Check(!ElevationSupport.CanElevateSameUser(true,TokenElevationKind.Full),"Already elevated must not re-launch");
   Check(!ElevationSupport.CanElevateSameUser(false,TokenElevationKind.Default),"Standard user must not silently switch to another administrator");
   Check(ElevationSupport.MakeArguments("S-1-5-21-555",true)=="--elevated-from-sid S-1-5-21-555 --resume --resident","Wrong resident handoff flags");
   Check(ElevationSupport.MakeArguments("S-1-5-21-555",false).EndsWith(" --resume"),"Missing support resume flag");
   Check(!ElevationSupport.ValidateSameUser("S-1-5-21-1","S-1-5-21-2"),"Different Windows SID accepted");
   bool bad=false;try{ElevationSupport.MakeArguments("S-1-5-21-1 & calc",false);}catch(ArgumentException){bad=true;}
   Check(bad,"Argument injection not rejected");
   Console.WriteLine("PASS: filtered-token UAC consent, no cross-user elevation, SID handoff guards");
   return 0;
  }catch(Exception e){Console.Error.WriteLine(e);return 1;}
 }
}
