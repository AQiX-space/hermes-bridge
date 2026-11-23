using System;
using HermesBridge;
class ReconnectPolicyTests {
 static int Main(){
  var p=new ReconnectPolicy();
  int[] expected={10,10,30,30,60,60,60,300,300};
  foreach(int n in expected){
   if(p.FailedDelay().TotalSeconds!=n)throw new Exception("Bad reconnect delay "+n);
  }
  p.Connected();
  if(p.Failures!=0||p.FailedDelay().TotalSeconds!=10)throw new Exception("Reconnect policy does not reset");
  Console.WriteLine("PASS: bounded reconnect without permission refresh");return 0;
 }
}
