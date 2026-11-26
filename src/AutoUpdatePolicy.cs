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
 }
}
