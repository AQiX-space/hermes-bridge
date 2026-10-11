using System;
using System.IO;
using System.Text;
using System.Security.Cryptography;
using System.Web.Script.Serialization;
using HermesBridge;

internal static class UpdateVerifyTests {
 static void Assert(bool yes,string what){if(!yes)throw new Exception("FAILED: "+what);Console.WriteLine("PASS: "+what);}
 static UpdateManifest Clone(UpdateManifest m){return new UpdateManifest{version=m.version,url=m.url,sha256=m.sha256,signature=m.signature};}
 static int Main(string[] args){
  if(args.Length!=1)throw new Exception("Fixture path required");
  UpdateManifest m=new JavaScriptSerializer().Deserialize<UpdateManifest>(File.ReadAllText(args[0],Encoding.UTF8));
  Assert(UpdateClient.Verify(m),"valid signed release manifest");
  var x=Clone(m);x.version="9.9.9.9";Assert(!UpdateClient.Verify(x),"tampered version rejected");
  x=Clone(m);x.sha256=new string('f',64);Assert(!UpdateClient.Verify(x),"tampered digest rejected");
  x=Clone(m);x.url="https://evil.example/bridge.exe";Assert(!UpdateClient.Verify(x),"wrong download origin rejected");
  x=Clone(m);x.url=m.url.Replace("https://","http://");Assert(!UpdateClient.Verify(x),"non-TLS download rejected");
  x=Clone(m);x.signature="AAAA";Assert(!UpdateClient.Verify(x),"bad signature rejected");
  x=Clone(m);x.url=m.url.Replace("/releases/","/other/");Assert(!UpdateClient.Verify(x),"wrong download path rejected");
  Assert(new Version(m.version)<new Version("0.2.0.1"),"prerelease numeric version ordering");
  Console.WriteLine("UPDATE CRYPTO TESTS: 8/8 PASSED");return 0;
 }
}
