using System;
using System.IO;
using System.Text;
namespace HermesBridge {
 public enum ConnectorMode { Support, Resident }
 public sealed class ConnectorPreferences {
  public ConnectorMode Mode=ConnectorMode.Support;
  public bool AutoDisconnect=false;
  public int DisconnectMinutes=60;
  public bool LogExpanded=false;
  public static ConnectorPreferences Load(string path){
   var result=new ConnectorPreferences();
   if(!File.Exists(path))return result;
   foreach(string line in File.ReadAllLines(path,Encoding.UTF8)){
    int equals=line.IndexOf('=');if(equals<1)continue;
    string key=line.Substring(0,equals).Trim(),value=line.Substring(equals+1).Trim();
    if(key=="mode")result.Mode=value=="resident"?ConnectorMode.Resident:ConnectorMode.Support;
    else if(key=="auto_disconnect")result.AutoDisconnect=value=="true";
    else if(key=="disconnect_minutes"){
     int n;if(int.TryParse(value,out n)&&n>=5&&n<=1440)result.DisconnectMinutes=n;
    }
    else if(key=="log_expanded")result.LogExpanded=value=="true";
   }
   if(result.Mode==ConnectorMode.Resident)result.AutoDisconnect=false;
   return result;
  }
  public void Save(string path){
   if(DisconnectMinutes<5||DisconnectMinutes>1440)throw new InvalidDataException("Invalid disconnect interval");
   string parent=Path.GetDirectoryName(path);if(String.IsNullOrEmpty(parent))throw new InvalidDataException("Invalid prefs path");
   Directory.CreateDirectory(parent);
   string body="mode="+(Mode==ConnectorMode.Resident?"resident":"support")+"\n"+
       "auto_disconnect="+(AutoDisconnect&&Mode==ConnectorMode.Support?"true":"false")+"\n"+
       "disconnect_minutes="+DisconnectMinutes+"\nlog_expanded="+(LogExpanded?"true":"false")+"\n";
   string stage=path+".new";
   File.WriteAllText(stage,body,Encoding.UTF8);
   try{if(File.Exists(path))File.Replace(stage,path,null);else File.Move(stage,path);}
   finally{if(File.Exists(stage))File.Delete(stage);}
  }
  public bool ShouldTimeOut(DateTime utcStarted,DateTime utcNow){
   return Mode==ConnectorMode.Support&&AutoDisconnect&&utcNow>=utcStarted.AddMinutes(DisconnectMinutes);
  }
 }
}
