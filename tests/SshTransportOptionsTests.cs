using System;
using HermesBridge;
class SshTransportOptionsTests {
 static void Check(bool predicate,string what){if(!predicate)throw new Exception(what);}
 static int Main(){
  var args=SshTransportOptions.Flags;
  Check(args.Contains("-o ConnectTimeout=10"),"Unbounded connect attempt");
  Check(args.Contains("-o ConnectionAttempts=1"),"Multiple connection attempts delay fallback");
  Check(args.Contains("-o ServerAliveInterval=30"),"Missing cryptographic SSH server keepalive");
  Check(args.Contains("-o ServerAliveCountMax=3"),"Dead channel may stay alive forever");
  Check(args.Contains("-o ExitOnForwardFailure=yes"),"Failed remote forward must abort");
  Check(!args.Contains("StrictHostKeyChecking=no"),"Host verification disabled");
  Console.WriteLine("PASS: bounded connect, keepalive and remote-forward failure options");
  return 0;
 }
}
