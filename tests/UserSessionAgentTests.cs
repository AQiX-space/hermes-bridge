using System;
using System.Text;
using System.IO;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Web.Script.Serialization;
using System.Collections.Generic;
using HermesBridge;
class UserSessionAgentTests {
 static readonly JavaScriptSerializer Json=new JavaScriptSerializer();
 static string Send(int port, string line){
  using(var client=new TcpClient("127.0.0.1",port)){
   client.SendTimeout=8000;client.ReceiveTimeout=8000;
   using(var stream=client.GetStream()){
    byte[] body=Encoding.UTF8.GetBytes(line+"\n");stream.Write(body,0,body.Length);stream.Flush();
    using(var reader=new StreamReader(stream,Encoding.UTF8))return reader.ReadLine();
   }
  }
 }
 static string Signed(string ticket,string script,string nonce){
  long now=(long)(DateTime.UtcNow-new DateTime(1970,1,1,0,0,0,DateTimeKind.Utc)).TotalSeconds;
  byte[] key;using(var sha=SHA256.Create())key=sha.ComputeHash(Encoding.UTF8.GetBytes("Hermes user-agent HMAC v1\n"+ticket));
  string mac;using(var hmac=new HMACSHA256(key))mac=Convert.ToBase64String(hmac.ComputeHash(Encoding.UTF8.GetBytes(now+"\n"+nonce+"\n"+script)));
  return Json.Serialize(new {ts=now,nonce=nonce,script=script,mac=mac});
 }
 static IDictionary<string,object> Unpack(string value){return Json.Deserialize<Dictionary<string,object>>(value);}
 static void Check(bool condition,string label){if(!condition)throw new Exception(label);}
 static int Main(){
  try{
   string ticket=Convert.ToBase64String(Guid.NewGuid().ToByteArray())+Convert.ToBase64String(Guid.NewGuid().ToByteArray());
   using(var agent=new UserSessionAgent(ticket)){
    string user=WindowsIdentity.GetCurrent().Name;
    Check(agent.UserName==user,"Incorrect interactive user identity");
    string nonce=Guid.NewGuid().ToString("N"),script="[System.Security.Principal.WindowsIdentity]::GetCurrent().Name";
    string valid=Signed(ticket,script,nonce);
    string bad=Signed(ticket+"x",script,Guid.NewGuid().ToString("N"));
    Check(Unpack(Send(agent.Port,bad))["error"].ToString()=="Unauthorized","Wrong ticket accepted");
    var success=Unpack(Send(agent.Port,valid));
    Check(Convert.ToBoolean(success["ok"]),"Valid signed request rejected");
    Check(success["user"].ToString()==user,"Operator identity differs from process identity");
    Check(success["stdout"].ToString().Trim()==user,"PowerShell ran as different Windows user");
    Check(Unpack(Send(agent.Port,valid))["error"].ToString()=="Unauthorized","Request replay accepted");
    Check(agent.Port>1024,"Agent bound privileged port");
    Console.WriteLine("PASS: current Windows account="+user);
    Console.WriteLine("PASS: signed user-context command; invalid token denied; replay denied");
   }
   return 0;
  }catch(Exception ex){Console.Error.WriteLine(ex);return 1;}
 }
}
