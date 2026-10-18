using System;
using System.IO;
using System.Text;
using System.Security.Cryptography;
namespace HermesBridge {
 static class TicketStore {
  public static void Write(string path,string ticket){
   if(String.IsNullOrWhiteSpace(ticket))throw new ArgumentException("Missing ticket");
   byte[] plain=Encoding.UTF8.GetBytes(ticket);
   byte[] cipher=ProtectedData.Protect(plain,null,DataProtectionScope.CurrentUser);
   string temp=path+".tmp";
   File.WriteAllText(temp,"dpapi:"+Convert.ToBase64String(cipher),Encoding.ASCII);
   if(File.Exists(path))File.Delete(path);
   File.Move(temp,path);
  }
  public static string Read(string path){
   string payload=File.ReadAllText(path,Encoding.ASCII).Trim();
   if(!payload.StartsWith("dpapi:",StringComparison.Ordinal))return payload; // legacy migration
   byte[] plain=ProtectedData.Unprotect(Convert.FromBase64String(payload.Substring(6)),null,DataProtectionScope.CurrentUser);
   return Encoding.UTF8.GetString(plain);
  }
 }
}
