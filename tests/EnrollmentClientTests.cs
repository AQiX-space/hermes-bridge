using System;
using System.IO;
using HermesBridge;
class EnrollmentClientTests {
 static void Check(bool b,string s){if(!b)throw new Exception("FAILED "+s);Console.WriteLine("PASS "+s);}
 static int Main(){
  string b64=Convert.ToBase64String(new byte[]{0,0,0,11,115,115,104,45,101,100,50,53,53,49,57,0,0,0,32,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32});
  var c=new EnrollmentConfig{host="router-mgmt.aqixnet.com",port=22471,slot=23001,hostkey="ssh-ed25519 "+b64};
  Check(EnrollmentClient.Valid(c),"valid pinned Gateway configuration");
  c.slot=0;Check(!EnrollmentClient.Valid(c),"reject invalid slot");c.slot=23001;
  c.hostkey="ssh-rsa "+b64;Check(!EnrollmentClient.Valid(c),"reject unsupported host key");c.hostkey="ssh-ed25519 "+b64;
  string d=Path.Combine(Path.GetTempPath(),"hermes-enroll-test-"+Guid.NewGuid().ToString("N"));
  try{EnrollmentClient.SaveApproved(c,d);Check(File.ReadAllText(Path.Combine(d,"known_hosts")).Contains("[router-mgmt.aqixnet.com]:22471 ssh-ed25519"),"saved pinned known_hosts");
   Check(File.ReadAllText(Path.Combine(d,"approved-bridge.cfg")).Contains("slot=23001"),"approved reverse port stored");
   string ticket=new String('A',43);string f=Path.Combine(d,"approval-ticket");
   EnrollmentClient.SaveTicket(f,ticket);
   Check(!File.ReadAllText(f).Contains(ticket),"approval bearer ticket encrypted at rest");
   Check(EnrollmentClient.LoadTicket(f)==ticket,"DPAPI ticket roundtrip");
   File.WriteAllText(f,ticket);Check(EnrollmentClient.LoadTicket(f)==ticket,"legacy plaintext ticket migration");
   Check(File.ReadAllText(f).StartsWith("dpapi:"),"legacy ticket encrypted after migration");}
  finally{if(Directory.Exists(d))Directory.Delete(d,true);}
  return 0;
 }
}
