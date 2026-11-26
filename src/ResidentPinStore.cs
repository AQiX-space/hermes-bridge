using System;
using System.IO;
using System.Text;
using System.Security.Cryptography;

namespace HermesBridge {
 // PIN protects GUI settings, not the OS, local process termination or the
 // user's right to withdraw remote-access consent. Scoped to current Windows
 // profile with DPAPI, a salted PBKDF2 verifier and persistent rate limiting.
 public sealed class ResidentPinStore {
  const int Iterations=120000;
  const string DefaultPin="1111";
  readonly string path;
  static readonly byte[] Purpose=Encoding.UTF8.GetBytes("Hermes Connector resident PIN v1");
  public ResidentPinStore(string filename){if(String.IsNullOrWhiteSpace(filename))throw new ArgumentException("Missing PIN path");path=filename;}
  sealed class Record {public byte[] Salt;public byte[] Hash;public int Failures;public long LockUntil;}
  static void ValidatePin(string pin){
   if(pin==null||pin.Length<4||pin.Length>12)throw new ArgumentException("PIN must be 4–12 digits");
   foreach(char ch in pin)if(ch<'0'||ch>'9')throw new ArgumentException("PIN must consist of decimal digits only");
  }
  static byte[] HashPin(string pin,byte[] salt){using(var derive=new Rfc2898DeriveBytes(pin,salt,Iterations))return derive.GetBytes(32);}
  static bool Equal(byte[] a,byte[] b){if(a==null||b==null||a.Length!=b.Length)return false;int d=0;for(int i=0;i<a.Length;i++)d|=a[i]^b[i];return d==0;}
  static Record Create(string pin){
   ValidatePin(pin);byte[] salt=new byte[16];using(var rng=RandomNumberGenerator.Create())rng.GetBytes(salt);
   return new Record{Salt=salt,Hash=HashPin(pin,salt)};
  }
  byte[] Encode(Record rec){
   string body="1|"+Convert.ToBase64String(rec.Salt)+"|"+Convert.ToBase64String(rec.Hash)+"|"+rec.Failures+"|"+rec.LockUntil;
   return ProtectedData.Protect(Encoding.UTF8.GetBytes(body),Purpose,DataProtectionScope.CurrentUser);
  }
  Record Read(){
   string text=Encoding.UTF8.GetString(ProtectedData.Unprotect(File.ReadAllBytes(path),Purpose,DataProtectionScope.CurrentUser));
   string[] parts=text.Split('|');
   if(parts.Length!=5||parts[0]!="1")throw new InvalidDataException("Invalid PIN file version");
   var r=new Record{Salt=Convert.FromBase64String(parts[1]),Hash=Convert.FromBase64String(parts[2])};
   if(r.Salt.Length!=16||r.Hash.Length!=32||!int.TryParse(parts[3],out r.Failures)||!long.TryParse(parts[4],out r.LockUntil)||r.Failures<0)
    throw new InvalidDataException("Corrupt PIN record");
   return r;
  }
  void Write(Record r){
   string folder=Path.GetDirectoryName(path);if(String.IsNullOrEmpty(folder))throw new InvalidDataException("PIN folder missing");
   Directory.CreateDirectory(folder);string staging=path+".tmp";
   File.WriteAllBytes(staging,Encode(r));
   try{if(File.Exists(path))File.Replace(staging,path,null);else File.Move(staging,path);}
   finally{if(File.Exists(staging))File.Delete(staging);}
  }
  public bool Exists{get{return File.Exists(path);}}
  public bool InitializeDefault(){
   if(Exists){Read();return false;}
   Write(Create(DefaultPin));return true;
  }
  public bool Verify(string pin,out int waitSeconds){
   waitSeconds=0;Record r=Read();long now=DateTime.UtcNow.Ticks;
   if(r.LockUntil>now){waitSeconds=(int)Math.Min(int.MaxValue,Math.Ceiling((r.LockUntil-now)/(double)TimeSpan.TicksPerSecond));return false;}
   bool valid=pin!=null&&pin.Length>=4&&pin.Length<=12&&Equal(HashPin(pin,r.Salt),r.Hash);
   if(valid){if(r.Failures!=0||r.LockUntil!=0){r.Failures=0;r.LockUntil=0;Write(r);}return true;}
   r.Failures=Math.Min(r.Failures+1,100);
   if(r.Failures>=5){int exponent=Math.Min((r.Failures-5)/5,6);r.LockUntil=DateTime.UtcNow.AddSeconds(Math.Min(3600,30*(1<<exponent))).Ticks;}
   Write(r);
   if(r.LockUntil>now)waitSeconds=(int)Math.Ceiling((r.LockUntil-now)/(double)TimeSpan.TicksPerSecond);
   return false;
  }
  public void Change(string currentPin,string newPin){
   ValidatePin(newPin);
   int wait;if(!Verify(currentPin,out wait))throw new UnauthorizedAccessException(wait>0?"PIN временно заблокирован":"Неверный текущий PIN");
   Write(Create(newPin));
  }
  public bool IsDefault(){Record r=Read();return Equal(HashPin(DefaultPin,r.Salt),r.Hash);}
 }
}
