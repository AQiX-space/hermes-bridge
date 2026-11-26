using System;
using System.Reflection;
using HermesBridge;
class UpdaterVersionTests {
 static void Check(bool condition,string why){if(!condition)throw new Exception(why);}
 static int Main(){
  try{
   Check(GitHubUpdater.CurrentTag=="v0.3.1","EXE metadata identifies wrong update version: "+GitHubUpdater.CurrentTag);
   var m=typeof(GitHubUpdater).GetMethod("VersionOf",BindingFlags.NonPublic|BindingFlags.Static);
   var legacy=(Version)m.Invoke(null,new object[]{"v0.2.9"});
   var beta1=(Version)m.Invoke(null,new object[]{"v0.3.0-beta.1"});
   var beta2=(Version)m.Invoke(null,new object[]{"v0.3.0-beta.2"});
   var current=(Version)m.Invoke(null,new object[]{"v0.3.1"});
   var future=(Version)m.Invoke(null,new object[]{"v0.3.2"});
   Check(legacy<beta1&&beta1<beta2&&beta2<current&&current<future,"Stable upgrade order is invalid");
   Console.WriteLine("PASS: 0.2.9 < beta.1 < beta.2 < 0.3.1 < 0.3.2; stable tag verified");
   return 0;
  }catch(Exception ex){Console.Error.WriteLine(ex);return 1;}
 }
}
