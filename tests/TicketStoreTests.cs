using System;
using System.IO;
using HermesBridge;
class Tests {
 static void Main(){
  string dir=Path.Combine(Path.GetTempPath(),"hermes-ticket-test-"+Guid.NewGuid().ToString("N"));
  Directory.CreateDirectory(dir);
  try{
   string path=Path.Combine(dir,"ticket");string ticket="aBcD0123456789_-secret-bearer";
   TicketStore.Write(path,ticket);
   string atRest=File.ReadAllText(path);
   if(atRest.Contains(ticket)||!atRest.StartsWith("dpapi:"))throw new Exception("Ticket leaked or not DPAPI-protected");
   if(TicketStore.Read(path)!=ticket)throw new Exception("DPAPI roundtrip failed");
   File.WriteAllText(path,ticket);
   if(TicketStore.Read(path)!=ticket)throw new Exception("Legacy ticket migration failed");
   TicketStore.Write(path,TicketStore.Read(path));
   if(!File.ReadAllText(path).StartsWith("dpapi:"))throw new Exception("Legacy ticket was not re-protected");
   Console.WriteLine("PASS Windows user-scoped DPAPI ticket persistence and legacy migration");
  }finally{Directory.Delete(dir,true);}
 }
}
