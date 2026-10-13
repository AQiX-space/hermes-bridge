using System;
using HermesBridge;
class SshEventsTests {
 static void Check(bool ok,string what){if(!ok)throw new Exception(what);Console.WriteLine("PASS "+what);}
 static int Main(){
  Check(SshEvents.ForwardReady("debug1: remote forward success for: listen 127.0.0.1 port 22472"),"forward readiness event");
  Check(!SshEvents.ForwardReady("debug1: Offering public key"),"authentication in progress is not connection");
  Check(!SshEvents.ForwardReady("debug1: remote forward failure"),"failed forward never ready");
  Check(SshEvents.HumanFailure("Permission denied (publickey).")!=null,"unregistered key guidance");
  Check(SshEvents.HumanFailure("Warning: remote port forwarding failed for listen port 22472")!=null,"restricted reverse port guidance");
  Check(SshEvents.HumanFailure("Host key verification failed.")!=null,"host key mismatch guidance");
  Check(SshEvents.HumanFailure("debug1: Entering interactive session.")==null,"ordinary debug log ignored");
  return 0;
 }
}
