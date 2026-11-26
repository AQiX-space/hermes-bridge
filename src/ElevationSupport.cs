using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;

namespace HermesBridge {
 public enum TokenElevationKind { Default=1, Full=2, Limited=3 }
 public static class ElevationSupport {
  const int TokenElevationType=18;
  [DllImport("advapi32.dll", SetLastError=true)]
  static extern bool GetTokenInformation(IntPtr tokenHandle, int tokenInformationClass,
    out int tokenInformation, int tokenInformationLength, out int returnLength);

  public static string CurrentSid(){
   using(var id=WindowsIdentity.GetCurrent())return id.User.Value;
  }
  public static string CurrentUser(){
   using(var id=WindowsIdentity.GetCurrent())return id.Name;
  }
  public static TokenElevationKind CurrentTokenKind(){
   using(var id=WindowsIdentity.GetCurrent()){
    int type,length;
    if(!GetTokenInformation(id.Token,TokenElevationType,out type,4,out length))
     throw new Win32Exception(Marshal.GetLastWin32Error());
    if(type<1||type>3)throw new InvalidOperationException("Unknown Windows token elevation type");
    return (TokenElevationKind)type;
   }
  }
  public static bool IsElevated(){
   using(var id=WindowsIdentity.GetCurrent())
    return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
  }
  // Limited means an administrator running under a filtered token. Default
  // non-admin must not use a DIFFERENT admin credential as a silent identity switch.
  public static bool CanElevateSameUser(bool isElevated,TokenElevationKind type){
   return !isElevated&&type==TokenElevationKind.Limited;
  }
  public static string MakeArguments(string sid,bool resident){
   if(String.IsNullOrEmpty(sid)||sid.Length>180)throw new ArgumentException("Invalid Windows SID");
   foreach(char c in sid)if(!Char.IsLetterOrDigit(c)&&c!='-')throw new ArgumentException("Invalid Windows SID");
   return "--elevated-from-sid "+sid+" --resume"+(resident?" --resident":"");
  }
  public static bool ValidateSameUser(string expectedSid,string actualSid){
   return String.Equals(expectedSid,actualSid,StringComparison.OrdinalIgnoreCase);
  }
  public static void StartElevated(string executable,string sid,bool resident){
   var info=new ProcessStartInfo(executable,MakeArguments(sid,resident)){
    Verb="runas",UseShellExecute=true,WorkingDirectory=System.IO.Path.GetDirectoryName(executable)
   };
   using(var process=Process.Start(info)){
    if(process==null)throw new InvalidOperationException("Windows did not launch the elevated process");
   }
  }
 }
}
