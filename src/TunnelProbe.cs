using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;

namespace HermesBridge {
 public static class TunnelProbe {
  // Used by acceptance tests and the GUI. A running ssh.exe is not proof of forwarding.
  public static int Run(string[] a) {
   if(a.Length!=6){Console.Error.WriteLine("usage: --probe host gatewayPort reversePort keyPath knownHostsPath seconds");return 2;}
   string host=a[0],key=a[3],known=a[4];int port,reverse,seconds;
   if(!int.TryParse(a[1],out port)||!int.TryParse(a[2],out reverse)||!int.TryParse(a[5],out seconds)||port<1||port>65535||reverse<1024||reverse>65535||seconds<2||seconds>60){Console.Error.WriteLine("invalid probe parameters");return 2;}
   if(!File.Exists(key)||!File.Exists(known)){Console.Error.WriteLine("key or known hosts absent");return 3;}
   if(host.Length>200||!System.Text.RegularExpressions.Regex.IsMatch(host,@"^[a-zA-Z0-9.-]+$")){Console.Error.WriteLine("invalid host");return 3;}
   string ssh=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),"OpenSSH","ssh.exe");
   string args="-vv -N -T -p "+port+" -R 127.0.0.1:"+reverse+":127.0.0.1:22 -i \""+key+"\" -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=\""+known+"\" -o ExitOnForwardFailure=yes -o ConnectTimeout=7 -o ServerAliveInterval=30 hermes-bridge@"+host;
   using(var p=new Process()){
    p.StartInfo=new ProcessStartInfo(ssh,args){UseShellExecute=false,CreateNoWindow=true,RedirectStandardError=true};
    var log=new StringBuilder();bool established=false;
    p.ErrorDataReceived+=(sender,e)=>{if(e.Data==null)return;lock(log){log.AppendLine(e.Data);if(e.Data.IndexOf("remote forward success",StringComparison.OrdinalIgnoreCase)>=0)established=true;}};
    try{p.Start();p.BeginErrorReadLine();}catch(Exception ex){Console.Error.WriteLine(ex.Message);return 4;}
    try{
     DateTime end=DateTime.UtcNow.AddSeconds(seconds);
     while(DateTime.UtcNow<end && !p.HasExited){lock(log){if(established){Console.WriteLine("PASS REMOTE_FORWARD_ESTABLISHED");return 0;}}Thread.Sleep(150);}
     string report;lock(log){report=log.ToString();}
     if(report.Length>4000)report=report.Substring(report.Length-4000);
     Console.Error.WriteLine(report);
     Console.Error.WriteLine("FAIL REMOTE_FORWARD_NOT_CONFIRMED");return 5;
    } finally{try{if(!p.HasExited)p.Kill();}catch{}}
   }
  }
 }
}
