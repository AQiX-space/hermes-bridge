using System;
namespace HermesBridge {
 // Transport retry schedule only. Does not renew or expand authorization.
 public sealed class ReconnectPolicy {
  int failures;
  public int Failures {get{return failures;}}
  public void Connected(){failures=0;}
  public TimeSpan FailedDelay(){
   failures=Math.Min(failures+1,1000);
   if(failures<=2)return TimeSpan.FromSeconds(10);
   if(failures<=4)return TimeSpan.FromSeconds(30);
   if(failures<=7)return TimeSpan.FromMinutes(1);
   return TimeSpan.FromMinutes(5);
  }
 }
}
