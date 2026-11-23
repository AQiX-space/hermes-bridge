using System;
using System.IO;
using System.Reflection;
using Microsoft.Win32;
using HermesBridge;
class WindowsStartupTests {
 static void Check(bool x,string msg){if(!x)throw new Exception(msg);}
 static int Main(){
  string target=WindowsStartup.InstalledPath();
  using(var key=Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run")){
   if(key!=null&&key.GetValue("HermesConnector")!=null)throw new Exception("Cannot test existing user's autostart state");
  }
  if(File.Exists(target))throw new Exception("Cannot overwrite existing user Connector");
  try{
   WindowsStartup.Enable(Assembly.GetExecutingAssembly().Location);
   Check(WindowsStartup.Enabled(),"Autostart not registered for this Windows user");
   Check(File.Exists(target),"Autostart executable not installed in user profile");
   WindowsStartup.Disable();
   Check(!WindowsStartup.Enabled(),"Autostart not removed when disabled");
   Console.WriteLine("PASS: opted-in HKCU autostart, user-scope copy and removal");return 0;
  }catch(Exception ex){Console.Error.WriteLine(ex);return 1;}
  finally{WindowsStartup.Disable();if(File.Exists(target))File.Delete(target);}
 }
}
