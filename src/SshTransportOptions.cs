namespace HermesBridge {
 // Common options for the resident SSH connection and its acceptance probe.
 // An unresponsive primary must never leave ssh.exe stuck indefinitely.
 public static class SshTransportOptions {
  public const int ConnectTimeoutSeconds=10;
  public const int AliveIntervalSeconds=30;
  public const int AliveMissLimit=3;
  public static readonly string Flags =
   "-o ExitOnForwardFailure=yes -o ConnectTimeout=10 -o ConnectionAttempts=1"+
   " -o ServerAliveInterval=30 -o ServerAliveCountMax=3 -o TCPKeepAlive=yes";
 }
}
