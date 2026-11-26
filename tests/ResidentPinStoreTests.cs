using System;
using System.IO;
using HermesBridge;
class ResidentPinStoreTests {
 static void Check(bool success,string msg){if(!success)throw new Exception(msg);}
 static int Main(){
  string root=Path.Combine(Path.GetTempPath(),"hermes-pin-test-"+Guid.NewGuid().ToString("N"));
  try{
   var store=new ResidentPinStore(Path.Combine(root,"pin.bin"));
   Check(store.InitializeDefault(),"First-use default not created");
   Check(!store.InitializeDefault(),"Existing PIN overwritten");
   int wait;
   Check(store.Verify("1111",out wait),"Default 1111 not accepted");
   Check(!store.Verify("2222",out wait),"Wrong PIN accepted");
   store.Change("1111","639204");
   Check(!store.Verify("1111",out wait),"Old PIN still valid");
   Check(store.Verify("639204",out wait),"Custom PIN rejected");
   bool invalid=false;try{store.Change("639204","abcd");}catch(ArgumentException){invalid=true;}
   Check(invalid,"Non-numeric PIN accepted");
   var bytes=File.ReadAllBytes(Path.Combine(root,"pin.bin"));
   Check(!System.Text.Encoding.UTF8.GetString(bytes).Contains("639204"),"Plaintext PIN in file");
   for(int i=0;i<5;i++)Check(!store.Verify("0000",out wait),"Invalid guess accepted");
   Check(wait>0,"Rate limit not enabled");
   var restarted=new ResidentPinStore(Path.Combine(root,"pin.bin"));
   Check(!restarted.Verify("639204",out wait)&&wait>0,"Restart bypassed cooldown");
   Console.WriteLine("PASS: default PIN, change, DPAPI verifier, persistent throttling and no plaintext");
   return 0;
  }catch(Exception e){Console.Error.WriteLine(e);return 1;}
  finally{try{if(Directory.Exists(root))Directory.Delete(root,true);}catch{}}
 }
}
