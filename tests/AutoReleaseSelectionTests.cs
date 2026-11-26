using System;
using HermesBridge;
class AutoReleaseSelectionTests {
 static void Check(bool state,string why){if(!state)throw new Exception(why);}
 static GitHubUpdater.Release Release(string version,bool draft,string digest,string url){
  return new GitHubUpdater.Release{tag_name="v"+version,draft=draft,
   assets=new[]{new GitHubUpdater.Asset{name="HermesBridge.exe",digest=digest,
    browser_download_url=url??("https://github.com/AQiX-space/hermes-bridge/releases/download/v"+version+"/HermesBridge.exe")}}};
 }
 static int Main(){
  string good="sha256:"+new string('a',64);
  var valid=Release("0.3.2",false,good,null);
  var draft=Release("9.0.0",true,good,null);
  var missing=Release("7.0.0",false,"",null);
  var forged=Release("8.0.0",false,good,"https://evil.example/bridge.exe");
  var invalid=Release("10.0.0",false,good,"https://github.com/other/repo/releases/download/v10.0.0/HermesBridge.exe");
  Check(GitHubUpdater.SelectLatest(new[]{draft,forged,missing,invalid,valid})==valid,"No valid higher release selected");
  Check(GitHubUpdater.SelectLatest(new[]{draft,forged,missing,invalid})==null,"Unsafe release accepted");
  Check(GitHubUpdater.SelectLatest(null)==null,"Null release API returned version");
  Check(GitHubUpdater.SelectLatest(new[]{Release("0.2.9",false,good,null)})==null,"Older version selected");
  Console.WriteLine("PASS: only newer non-draft GitHub release with pinned source and SHA256 offered");
  return 0;
 }
}
