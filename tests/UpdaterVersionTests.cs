using System;
using System.Reflection;
using HermesBridge;
class UpdaterVersionTests {
 static void Check(bool condition,string why){if(!condition)throw new Exception(why);}
 static int Main(){
  try{
   Check(GitHubUpdater.CurrentTag=="v0.3.0-beta.2","EXE metadata identifies wrong update version: "+GitHubUpdater.CurrentTag);
   var m=typeof(GitHubUpdater).GetMethod("VersionOf",BindingFlags.NonPublic|BindingFlags.Static);
   var older=(Version)m.Invoke(null,new object[]{"v0.2.9"});
   var current=(Version)m.Invoke(null,new object[]{"v0.3.0-beta.2"});
   var next=(Version)m.Invoke(null,new object[]{"v0.3.0-beta.3"});
   var stable=(Version)m.Invoke(null,new object[]{"v0.3.0"});
   Check(older<current,"0.2.9 incorrectly outranks beta 0.3.0");
   Check(current<next&&next<stable,"Prerelease ordering invalid");
   Console.WriteLine("PASS: published 0.2.9 < current 0.3.0-beta.2 < beta.3 < stable 0.3.0");
   return 0;
  }catch(Exception ex){Console.Error.WriteLine(ex);return 1;}
 }
}
