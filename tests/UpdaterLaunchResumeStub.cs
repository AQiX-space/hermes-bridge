using System;
using System.IO;
using System.Reflection;
using System.Threading;
[assembly: AssemblyProduct("Hermes Connector")]
class UpdaterLaunchResumeStub {
 static void Main(string[] args){
  File.WriteAllText(Assembly.GetExecutingAssembly().Location+".argv",String.Join(" ",args));
  Thread.Sleep(3200);
 }
}
