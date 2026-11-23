using System;
using System.IO;
using System.Security.Cryptography;
using Microsoft.Win32;
namespace HermesBridge {
 public static class WindowsStartup {
  const string KeyPath=@"Software\Microsoft\Windows\CurrentVersion\Run";
  const string ValueName="HermesConnector";
  public static string InstalledPath(){
   return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"HermesBridge","HermesConnector.exe");
  }
  public static bool Enabled(){
   using(var key=Registry.CurrentUser.OpenSubKey(KeyPath,false)){
    return key!=null&&String.Equals(Convert.ToString(key.GetValue(ValueName)),"\""+InstalledPath()+"\" --resident",StringComparison.OrdinalIgnoreCase);
   }
  }
  public static void Enable(string launchedExecutable){
   string source=Path.GetFullPath(launchedExecutable),target=Path.GetFullPath(InstalledPath());
   if(!File.Exists(source))throw new FileNotFoundException("Connector binary is missing",source);
   if(!String.Equals(source,target,StringComparison.OrdinalIgnoreCase)){
    Directory.CreateDirectory(Path.GetDirectoryName(target));
    string stage=target+".staging";
    if(File.Exists(stage))File.Delete(stage);
    File.Copy(source,stage);
    using(var a=File.OpenRead(source))using(var b=File.OpenRead(stage))using(var sha=SHA256.Create()){
     byte[] first=sha.ComputeHash(a),second=sha.ComputeHash(b);
     if(!Equal(first,second)){File.Delete(stage);throw new IOException("Copied Connector hash mismatch");}
    }
    try{if(File.Exists(target))File.Replace(stage,target,target+".previous");else File.Move(stage,target);}
    finally{if(File.Exists(stage))File.Delete(stage);}
   }
   using(var key=Registry.CurrentUser.CreateSubKey(KeyPath)){
    key.SetValue(ValueName,"\""+target+"\" --resident",RegistryValueKind.String);
   }
  }
  static bool Equal(byte[] x,byte[] y){
   if(x.Length!=y.Length)return false;int difference=0;
   for(int i=0;i<x.Length;i++)difference|=x[i]^y[i];return difference==0;
  }
  public static void Disable(){
   using(var key=Registry.CurrentUser.OpenSubKey(KeyPath,true))if(key!=null)key.DeleteValue(ValueName,false);
  }
 }
}
