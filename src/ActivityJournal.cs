using System;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
namespace HermesBridge {
 // Per-user, size-limited journal. Never persist broker tickets, passphrases
 // or short enrollment codes. No network or shell actions from logger.
 public sealed class ActivityJournal {
  readonly string path;
  readonly object sync=new object();
  const int MaxBytes=512*1024;
  static readonly Regex EnrollmentCode=new Regex(@"(?i)(Код\s+МОСТ\s*:\s*)[A-Z0-9-]+",RegexOptions.Compiled|RegexOptions.CultureInvariant);
  static readonly Regex ParameterSecret=new Regex(@"(?i)\b(ticket|token|secret|password|passphrase|authorization|api[_-]?key|mac)\s*[:=]\s*\S+",RegexOptions.Compiled|RegexOptions.CultureInvariant);
  public ActivityJournal(string filename){
   if(String.IsNullOrWhiteSpace(filename))throw new ArgumentException("Journal file path required", "filename");
   path=Path.GetFullPath(filename);
  }
  public static string Sanitize(string message){
   if(String.IsNullOrWhiteSpace(message))return "";
   string limited=message.Length>2048?message.Substring(0,2048):message;
   limited=limited.Replace('\r',' ').Replace('\n',' ');
   limited=EnrollmentCode.Replace(limited,"$1[скрыт]");
   limited=ParameterSecret.Replace(limited,m=>m.Groups[1].Value+"=[скрыто]");
   return limited;
  }
  public void Append(string message){
   string sanitized=Sanitize(message);
   if(sanitized.Length==0)return;
   string line=DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss")+" "+sanitized+Environment.NewLine;
   byte[] bytes=Encoding.UTF8.GetBytes(line);
   lock(sync){
    string directory=Path.GetDirectoryName(path);
    Directory.CreateDirectory(directory);
    using(var stream=new FileStream(path,FileMode.OpenOrCreate,FileAccess.ReadWrite,FileShare.Read)){
     // Preserve the most recent 50% without retaining unlimited history.
     if(stream.Length+bytes.Length>MaxBytes){
      int capacity=MaxBytes/2;
      int count=(int)Math.Min(capacity,stream.Length);
      stream.Position=stream.Length-count;
      byte[] suffix=new byte[count];
      int read=0;while(read<count){int n=stream.Read(suffix,read,count-read);if(n==0)break;read+=n;}
      int offset=0;
      // Start at next newline: no truncated secret-containing entry fragments.
      while(offset<read && suffix[offset]!=10)offset++;
      if(offset<read)offset++;
      stream.Position=0;
      stream.Write(suffix,offset,read-offset);
      stream.SetLength(read-offset);
     }
     stream.Position=stream.Length;
     stream.Write(bytes,0,bytes.Length);
     stream.Flush();
    }
   }
  }
  public string Tail(int maxChars=12000){
   if(maxChars<1||maxChars>65536)throw new ArgumentOutOfRangeException("maxChars");
   lock(sync){
    if(!File.Exists(path))return "";
    using(var stream=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.ReadWrite)){
     int length=(int)Math.Min(stream.Length,Math.Min(MaxBytes,maxChars*4));
     stream.Position=stream.Length-length;
     byte[] buffer=new byte[length];int total=0;
     while(total<length){int n=stream.Read(buffer,total,length-total);if(n==0)break;total+=n;}
     string text=Encoding.UTF8.GetString(buffer,0,total);
     if(text.Length>maxChars)text=text.Substring(text.Length-maxChars);
     int first=text.IndexOf('\n');
     if(stream.Length>length&&first>=0)text=text.Substring(first+1);
     return text;
    }
   }
  }
 }
}
