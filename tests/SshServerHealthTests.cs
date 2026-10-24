using System;
using HermesBridge;
class SshServerHealthTests {
 static void Assert(bool ok,string message){if(!ok)throw new Exception(message);}
 static void Main(){
  Assert(SshServerHealth.Evaluate(false,"missing",false,false,true).State==SshServerState.ClientMissing,"client missing");
  Assert(SshServerHealth.Evaluate(true,"missing",false,false,true).State==SshServerState.ServerMissing,"server missing");
  Assert(SshServerHealth.Evaluate(true,"stopped",false,false,true).State==SshServerState.ServerStopped,"server stopped");
  Assert(SshServerHealth.Evaluate(true,"running",false,false,true).State==SshServerState.PortClosed,"port closed");
  Assert(SshServerHealth.Evaluate(true,"running",true,false,true).State==SshServerState.WrongProtocol,"not SSH protocol");
  Assert(SshServerHealth.Evaluate(true,"unknown",true,true,true).State==SshServerState.Unknown,"unknown must fail closed");
  Assert(SshServerHealth.Evaluate(true,"running",true,true,true).Ready,"SSH ready");
  Assert(!SshServerHealth.Evaluate(true,"missing",false,false,false).Ready,"unsupported OS fail closed");
  Console.WriteLine("PASS: OpenSSH Server readiness classification");
 }
}
