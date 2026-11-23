using System;
using System.IO;
using HermesBridge;
class ActivityJournalTests {
 static void Check(bool ok,string label){if(!ok)throw new Exception(label);}
 static int Main(){
  string dir=Path.Combine(Path.GetTempPath(),"hermes-journal-"+Guid.NewGuid().ToString("N"));
  try{
   var journal=new ActivityJournal(Path.Combine(dir,"events.log"));
   journal.Append("Код МОСТ: DE49 · Назови его при подтверждении");
   journal.Append("token=abc123 password: foo api_key=x secret=z");
   journal.Append("Подключение успешно");
   var replay=new ActivityJournal(Path.Combine(dir,"events.log"));
   string text=replay.Tail();
   Check(text.Contains("Подключение успешно"),"Journal not persistent");
   Check(!text.Contains("DE49")&&!text.Contains("abc123")&&!text.Contains("foo")&&!text.Contains("api_key=x"),"Secret leaked in journal");
   for(int i=0;i<8000;i++)journal.Append("reconnect #"+i+"  "+new String('z',100));
   var file=new FileInfo(Path.Combine(dir,"events.log"));
   Check(file.Length<=512*1024,"Journal size unbounded");
   Check(journal.Tail(4000).Contains("reconnect #7999"),"Newest event lost after rollover");
   Console.WriteLine("PASS: sanitized, persistent, bounded activity log and rollover");return 0;
  }catch(Exception e){Console.Error.WriteLine(e);return 1;}
  finally{if(Directory.Exists(dir))Directory.Delete(dir,true);}
 }
}
