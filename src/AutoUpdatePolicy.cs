using System;
namespace HermesBridge {
 public static class AutoUpdatePolicy {
  // Active reverse SSH is safe to pause: preserve encrypted registration and
  // server approval, then resume after updater's atomic swap. Enrollment and
  // revocation are never interrupted by background updates.
  public static bool CanUpdate(bool quitting,bool alreadyUpdating,bool enrolling,bool revoking,bool revocationPending){
   return !quitting&&!alreadyUpdating&&!enrolling&&!revoking&&!revocationPending;
  }
  public static bool ResumeAfterSwap(bool wasConnected,bool wasResident){
   return wasConnected||wasResident;
  }
  public static bool IsQuarantined(string sha256,string record,DateTime nowUtc){
   if(String.IsNullOrEmpty(sha256)||sha256.Length!=64||String.IsNullOrEmpty(record)||record.Length>160)return false;
   var parts=record.Trim().Split('|');if(parts.Length!=2||!String.Equals(sha256,parts[0],StringComparison.OrdinalIgnoreCase))return false;
   long ticks;if(!long.TryParse(parts[1],out ticks))return false;
   try{
    var failedAt=new DateTime(ticks,DateTimeKind.Utc);
    var elapsed=nowUtc.ToUniversalTime()-failedAt;
    return elapsed>=TimeSpan.Zero&&elapsed<TimeSpan.FromHours(24);
   }catch{return false;}
  }
 }
}
