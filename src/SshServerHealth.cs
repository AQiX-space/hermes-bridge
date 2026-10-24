using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.ServiceProcess;
using Microsoft.Win32;

namespace HermesBridge {
 enum SshServerState { ClientMissing, ServerMissing, ServerStopped, PortClosed, WrongProtocol, Unknown, Ready }
 sealed class SshServerHealth {
  public SshServerState State { get; private set; }
  public string Explanation { get; private set; }
  public bool WindowsCapabilitySupported { get; private set; }
  public bool Ready { get { return State == SshServerState.Ready; } }

  internal static SshServerHealth Evaluate(bool client, string service, bool port, bool sshBanner, bool supported) {
   var result = new SshServerHealth { WindowsCapabilitySupported = supported };
   if (!client) { result.State=SshServerState.ClientMissing; result.Explanation="OpenSSH Client отсутствует"; }
   else if (service=="missing") { result.State=SshServerState.ServerMissing; result.Explanation="OpenSSH Server не установлен (служба sshd отсутствует)"; }
   else if (service=="stopped") { result.State=SshServerState.ServerStopped; result.Explanation="OpenSSH Server установлен, служба sshd остановлена"; }
   else if (service!="running") { result.State=SshServerState.Unknown; result.Explanation="Состояние службы sshd не удалось проверить"; }
   else if (!port) { result.State=SshServerState.PortClosed; result.Explanation="sshd работает, но 127.0.0.1:22 недоступен"; }
   else if (!sshBanner) { result.State=SshServerState.WrongProtocol; result.Explanation="Порт 22 отвечает, но не возвращает приветствие SSH"; }
   else { result.State=SshServerState.Ready; result.Explanation="OpenSSH Server отвечает локально по SSH"; }
   return result;
  }

  public static bool SupportsWindowsCapability() {
   try {
    using(var key=Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion")) {
     int build;
     return key!=null && int.TryParse(Convert.ToString(key.GetValue("CurrentBuildNumber")), out build) && build>=17763;
    }
   } catch { return false; }
  }

  public static SshServerHealth Probe(string clientExe) {
   bool client=File.Exists(clientExe);
   bool supported=SupportsWindowsCapability();
   if(!client)return Evaluate(false,"missing",false,false,supported);
   string service="unknown";
   try {
    using(var ctl=new ServiceController("sshd")) {
     ServiceControllerStatus s=ctl.Status;
     service=s==ServiceControllerStatus.Running?"running":"stopped";
    }
   } catch(InvalidOperationException) { service="missing"; }
   catch(System.ComponentModel.Win32Exception) { service="unknown"; }
   if(service!="running")return Evaluate(client,service,false,false,supported);
   bool port=false,banner=false;
   try {
    using(var socket=new TcpClient()) {
     var connect=socket.ConnectAsync(IPAddress.Loopback,22);
     if(connect.Wait(1200) && socket.Connected) {
      port=true;
      socket.ReceiveTimeout=1800;
      using(var stream=socket.GetStream()) {
       var line=new System.Text.StringBuilder();
       // RFC 4253 allows optional identification preamble lines before SSH-2.0.
       for(int i=0;i<512;i++) {
        int ch=stream.ReadByte();
        if(ch<0)break;
        if(ch==10) {
         string text=line.ToString().TrimEnd('\r');
         if(text.StartsWith("SSH-2.0-",StringComparison.Ordinal)||text.StartsWith("SSH-1.99-",StringComparison.Ordinal)){banner=true;break;}
         line.Clear();
        } else if(ch!=13)line.Append((char)ch);
       }
      }
     }
    }
   } catch { /* Local SSH is unhealthy; never claim remote operator access. */ }
   return Evaluate(client,service,port,banner,supported);
  }
 }
}
