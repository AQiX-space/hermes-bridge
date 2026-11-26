using System;
using System.IO;
using System.Net;
using System.Text;
using System.Linq;
using System.Diagnostics;
using System.Drawing;
using System.Windows.Forms;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Threading.Tasks;

namespace HermesBridge {
 static class App {
  [STAThread] static void Main(string[] args){
   if(args.Length>0 && args[0]=="--probe"){
    var a=new string[args.Length-1];Array.Copy(args,1,a,0,a.Length);
    Environment.ExitCode=TunnelProbe.Run(a);return;
   }
   bool resident=false,resume=false,resumeUpdate=false;
   string expectedSid=null;
   for(int i=0;i<args.Length;i++){
    if(args[i]=="--resident")resident=true;
    else if(args[i]=="--resume")resume=true;
    else if(args[i]=="--resume-update")resumeUpdate=true;
    else if(args[i]=="--elevated-from-sid"&&i+1<args.Length)expectedSid=args[++i];
    else{MessageBox.Show("Неверный параметр запуска коннектора.","Hermes Connector",MessageBoxButtons.OK,MessageBoxIcon.Warning);return;}
   }
   string sid=ElevationSupport.CurrentSid();
   if(expectedSid!=null&&(!ElevationSupport.ValidateSameUser(expectedSid,sid)||!ElevationSupport.IsElevated())){
    MessageBox.Show("Windows UAC запустил приложение под другой учётной записью либо без повышения прав. " +
      "Текущая регистрация МОСТ не переносится к другому пользователю.",
      "Hermes Connector — безопасность",MessageBoxButtons.OK,MessageBoxIcon.Warning);return;
   }
   if(resume&&expectedSid==null){
    MessageBox.Show("Автоматическое восстановление разрешено только при подтверждённом UAC-переходе.","Hermes Connector");return;
   }
   using(var single=new SingleInstanceGate(sid,expectedSid!=null||resumeUpdate)){
    if(!single.Acquired){
     if(!resident)MessageBox.Show("Hermes Connector уже запущен для этой учётной записи. Проверь значок в области уведомлений Windows.","Hermes Connector",MessageBoxButtons.OK,MessageBoxIcon.Information);
     return;
    }
    Application.EnableVisualStyles();Application.SetCompatibleTextRenderingDefault(false);
    Application.Run(new BridgeForm(resident,resume||resumeUpdate,resumeUpdate));
   }
  }
 }
 sealed class BridgeForm : Form {
  readonly bool launchResident,resumeAfterElevation,resumeAfterAutoUpdate;
  ConnectorPreferences preferences=new ConnectorPreferences(); ActivityJournal journal; ResidentPinStore residentPin;
  bool loadingPrefs=false;DateTime sessionStarted=DateTime.MinValue;
  string PrefsPath {get{return Path.Combine(root,"ui-preferences.ini");}}
  readonly string root=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"HermesBridge");
  TextBox host=new TextBox(),port=new TextBox(),slot=new TextBox(),known=new TextBox(),device=new TextBox();
  NumericUpDown ttl=new NumericUpDown(); CheckBox autoDisconnect=new CheckBox(); Label mostCode=new Label(); Label state=new Label(); Button start=new Button(),stop=new Button(),reload=new Button(),save=new Button(),import=new Button();
  NotifyIcon tray=new NotifyIcon(); ToolStripMenuItem trayToggle; Icon connectedTrayIcon; System.Windows.Forms.Timer heartbeat=new System.Windows.Forms.Timer();
  Process tunnel; UserSessionAgent userAgent; DateTime deadline; bool running=false, quitting=false, updating=false, forwardConfirmed=false, enrolling=false, cancelEnrollment=false; int enrollmentGeneration=0; string lastTunnelFailure="";
  string Config {get{return Path.Combine(root,"client.ini");}}
  string Ssh {get{return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),"OpenSSH","ssh.exe");}}
  string Key {get{return Path.Combine(root,"keys","device_ed25519");}}
  string Known {get{return Path.Combine(root,"known_hosts");}}
  Panel advanced=new Panel(); Label subtitle=new Label(), deviceInfo=new Label(), connectionInfo=new Label(), expiryInfo=new Label(); Button setup=new Button(), keyCopy=new Button(), shortcut=new Button(); LinkLabel updates=new LinkLabel(); System.Windows.Forms.Timer updateTimer=new System.Windows.Forms.Timer();
  TextBox actionLog=new TextBox(); Label sshInfo=new Label(); LinkLabel elevateLink=new LinkLabel(); ToolStripMenuItem elevateMenu; bool elevating=false; Button uninstall=new Button(), closeApp=new Button(), copyLog=new Button(); LinkLabel installSsh=new LinkLabel(), sshCheck=new LinkLabel(), sshServerInstall=new LinkLabel(), emergencyLink=new LinkLabel(); Button logToggle=new Button(); Label logTitle=new Label(); string sshVersion=null; SshServerHealth sshHealth; bool sshHealthBusy=false; DateTime nextSshHealth=DateTime.MinValue; bool updateAvailable=false; string activeMostCode=""; bool revoking=false; bool revocationPending=false; bool leaseCheckBusy=false; bool tickBusy=false; DateTime nextLeaseCheck=DateTime.MinValue; string gatewayMode="auto", enrollmentApi=GatewayEndpoints.Primary; ToolStripMenuItem gatewayMenu; ToolStripMenuItem recoverMenu; ToolStripMenuItem modeMenu; ToolStripMenuItem disableStartupMenu; ToolStripMenuItem codeMenu; ToolStripMenuItem pinMenu; string announcedCode="";
  Color ink=Color.FromArgb(37,31,25), muted=Color.FromArgb(115,99,83), blue=Color.FromArgb(150,85,41), surface=Color.FromArgb(248,244,238);
  public BridgeForm(bool startedAsResident=false,bool resumeAfterUac=false,bool resumeAfterUpdater=false){
   launchResident=startedAsResident;resumeAfterElevation=resumeAfterUac;resumeAfterAutoUpdate=resumeAfterUpdater;
   Text="Hermes Connector 0.3.0-beta.2"; Width=495;Height=578;MinimumSize=new Size(495,578);MaximumSize=new Size(900,578);StartPosition=FormStartPosition.CenterScreen;
   Font=new Font("Segoe UI",10f);BackColor=Color.White;ForeColor=ink;FormBorderStyle=FormBorderStyle.FixedSingle;MaximizeBox=false;
   Directory.CreateDirectory(root);Directory.CreateDirectory(Path.Combine(root,"keys"));journal=new ActivityJournal(Path.Combine(root,"activity.log"));residentPin=new ResidentPinStore(Path.Combine(root,"resident-pin.bin"));
   Label heading=new Label(){Text="Hermes Connector",Font=new Font("Segoe UI Semibold",19,FontStyle.Bold),Left=30,Top=24,Width=388,Height=42};Controls.Add(heading);
   subtitle=new Label(){Text="0.3.0-beta.2 · сеанс пользователя",ForeColor=muted,Left=31,Top=74,Width=255,Height=27};Controls.Add(subtitle);
   Panel card=new Panel(){Left=28,Top=167,Width=403,Height=130,BackColor=surface};Controls.Add(card);
   state.Left=17;state.Top=12;state.Width=250;state.Height=44;state.Font=new Font("Segoe UI Semibold",17,FontStyle.Bold);card.Controls.Add(state);
   connectionInfo.Left=18;connectionInfo.Top=54;connectionInfo.Width=368;connectionInfo.Height=30;connectionInfo.ForeColor=muted;card.Controls.Add(connectionInfo);
   deviceInfo.Left=18;deviceInfo.Top=94;deviceInfo.Width=368;deviceInfo.Height=28;deviceInfo.ForeColor=muted;card.Controls.Add(deviceInfo);
   mostCode.SetBounds(273,14,119,32);mostCode.Font=new Font("Consolas",12,FontStyle.Bold);mostCode.TextAlign=ContentAlignment.MiddleRight;card.Controls.Add(mostCode);
   start.Text="Подключить Гермеса";start.Left=28;start.Top=312;start.Width=403;start.Height=48;start.FlatStyle=FlatStyle.Flat;start.FlatAppearance.BorderSize=0;start.BackColor=Color.FromArgb(36,133,78);start.ForeColor=Color.White;start.Font=new Font("Segoe UI Semibold",12,FontStyle.Bold);Controls.Add(start);
   stop.Text="Отключить Гермеса";stop.Left=28;stop.Top=312;stop.Width=403;stop.Height=48;stop.FlatStyle=FlatStyle.Flat;stop.BackColor=Color.White;stop.ForeColor=Color.White;Controls.Add(stop);
   setup.Text="Настройки и регистрация  ▾";setup.Left=22;setup.Top=384;setup.Width=395;setup.Height=40;setup.FlatStyle=FlatStyle.Flat;setup.ForeColor=muted;Controls.Add(setup);
   updates.Text="Проверить";updates.SetBounds(337,77,94,24);updates.TextAlign=ContentAlignment.MiddleRight;updates.LinkColor=blue;updates.ActiveLinkColor=blue;Controls.Add(updates);
   updates.Click+=async (s,e)=>await CheckAndInstallUpdateAsync(false);
   emergencyLink.Text="Аварийно на GR2";
   emergencyLink.SetBounds(295,150,140,19);
   emergencyLink.TextAlign=ContentAlignment.MiddleRight;
   emergencyLink.LinkColor=Color.FromArgb(176,56,56);
   emergencyLink.Click+=async (sender,e)=>await RecoverFromDeadGateAsync();
   Controls.Add(emergencyLink);
   expiryInfo.Left=30;expiryInfo.Top=462;expiryInfo.Width=400;expiryInfo.Height=24;expiryInfo.ForeColor=muted;Controls.Add(expiryInfo);
   advanced.Left=0;advanced.Top=505;advanced.Width=495;advanced.Height=280;advanced.Visible=false;Controls.Add(advanced);
   int y=5;AddLine("Устройство",device,ref y);AddLine("Сервер",host,ref y);AddLine("Порт сервера",port,ref y);AddLine("Порт сессии",slot,ref y);
   ttl.Minimum=5;ttl.Maximum=1440;ttl.Value=60;ttl.Left=270;ttl.Top=y;ttl.Width=90;
   advanced.Controls.Add(new Label(){Text="Сессия, минут",Left=26,Top=y+4,Width=240});advanced.Controls.Add(ttl);y+=35;
   known.Visible=false;
   keyCopy=new Button(){Text="Скопировать ключ",Left=25,Top=y,Width=208,Height=32};advanced.Controls.Add(keyCopy);
   import.Text="Импорт регистрации";import.Left=249;import.Top=y;import.Width=208;import.Height=32;advanced.Controls.Add(import);
   shortcut.Text="Ярлык на рабочем столе";shortcut.Left=25;shortcut.Top=y+39;shortcut.Width=432;shortcut.Height=32;advanced.Controls.Add(shortcut);
   shortcut.Click+=(s,e)=>CreateDesktopShortcut();
   save.Text="Сохранить";save.Left=25;save.Top=y+78;save.Width=208;save.Height=32;advanced.Controls.Add(save);
   reload.Text="Перечитать";reload.Left=249;reload.Top=y+78;reload.Width=208;reload.Height=32;advanced.Controls.Add(reload);
   advanced.Height=y+119;
   keyCopy.Click+=(s,e)=>{if(EnsureKey()){Clipboard.SetText(File.ReadAllText(Key+".pub"));Status("Ключ скопирован. Нужна регистрация на шлюзе.");}};
   import.Click+=(s,e)=>ImportProvision();save.Click+=(s,e)=>SaveSettings();reload.Click+=async (s,e)=>{if(await EnsureRevokedAsync())LoadSettings();else Status("Перезагрузка настроек отменена: Gate не подтвердил отзыв.");};
   start.Click+=async (s,e)=>await StartOrEnrollAsync();stop.Click+=async (s,e)=>await DisconnectAsync();
   setup.Visible=false;advanced.Visible=false;
   stop.BackColor=Color.FromArgb(176,56,56);stop.FlatAppearance.BorderSize=0;
   sshInfo.SetBounds(31,103,285,45);sshInfo.ForeColor=muted;Controls.Add(sshInfo);
   elevateLink.Text="Перезапустить от администратора";
   elevateLink.SetBounds(31,147,250,20);elevateLink.LinkColor=Color.FromArgb(176,56,56);
   elevateLink.Click+=(sender,e)=>RestartAsAdministrator();Controls.Add(elevateLink);
   installSsh.Text="Установить сервер";installSsh.SetBounds(303,123,128,25);installSsh.TextAlign=ContentAlignment.MiddleRight;installSsh.LinkColor=blue;Controls.Add(installSsh);
   sshCheck.Text="Проверить";sshCheck.SetBounds(303,123,128,25);sshCheck.TextAlign=ContentAlignment.MiddleRight;sshCheck.LinkColor=blue;Controls.Add(sshCheck);
   sshCheck.Click+=(s,e)=>Status("Текущий пользователь: "+WindowsIdentity.GetCurrent().Name+". Подключение не требует Windows SSH Server.");
   installSsh.Click+=async (s,e)=>await InstallOpenSshAsync(SshComponent.Client);
   sshServerInstall.Text="Установить SSH Server";sshServerInstall.SetBounds(284,146,147,22);sshServerInstall.TextAlign=ContentAlignment.MiddleRight;sshServerInstall.LinkColor=blue;Controls.Add(sshServerInstall);
   sshServerInstall.Click+=async (s,e)=>await InstallOpenSshAsync(SshComponent.Server);
   shortcut.Parent= this;shortcut.SetBounds(28,376,190,37);shortcut.Visible=true;
   closeApp.Text="Закрыть Connector";closeApp.SetBounds(230,376,201,37);closeApp.Click+=async (s,e)=>await ExitWithRevokeAsync();Controls.Add(closeApp);
   logTitle=new Label(){Text="Журнал действий",Left=467,Top=33,Width=376,Height=28,Font=new Font("Segoe UI Semibold",13,FontStyle.Bold)};Controls.Add(logTitle);
   actionLog.SetBounds(463,78,395,440);actionLog.Multiline=true;actionLog.ScrollBars=ScrollBars.Vertical;actionLog.ReadOnly=true;actionLog.BorderStyle=BorderStyle.FixedSingle;actionLog.BackColor=Color.FromArgb(251,249,246);actionLog.ForeColor=ink;actionLog.Font=new Font("Consolas",9);Controls.Add(actionLog);
   copyLog.Text="Копировать журнал";copyLog.SetBounds(674,528,184,30);copyLog.Click+=(s,e)=>Clipboard.SetText(actionLog.Text);Controls.Add(copyLog);
   logToggle.Text="Журнал действий  ▸";logToggle.SetBounds(28,483,403,31);Controls.Add(logToggle);
   logToggle.Click+=(sender,e)=>SetLogExpanded(!preferences.LogExpanded);
   autoDisconnect.Text="Автоматическое отключение";autoDisconnect.SetBounds(30,429,238,28);autoDisconnect.Checked=false;Controls.Add(autoDisconnect);
   ttl.Parent=this;ttl.SetBounds(302,429,75,28);ttl.Minimum=5;ttl.Maximum=1440;ttl.Value=60;ttl.Enabled=false;
   autoDisconnect.CheckedChanged+=(sender,e)=>{ttl.Enabled=autoDisconnect.Checked;if(loadingPrefs)return;if(running){sessionStarted=DateTime.UtcNow;UpdateDeadline();}SavePreferences();Status("Настройки таймера изменены.");};
   ttl.ValueChanged+=(sender,e)=>{if(loadingPrefs)return;if(running){sessionStarted=DateTime.UtcNow;UpdateDeadline();}SavePreferences();};
   Controls.Add(new Label(){Text="мин",Left=384,Top=434,Width=45});
   uninstall.Text="Полностью удалить Connector";uninstall.SetBounds(28,524,403,30);uninstall.FlatStyle=FlatStyle.Flat;uninstall.ForeColor=Color.FromArgb(176,56,56);Controls.Add(uninstall);
   uninstall.Click+=async (s,e)=>await UninstallConnectorAsync();
   UpdateSshState();
   Icon=System.Drawing.Icon.ExtractAssociatedIcon(System.Reflection.Assembly.GetExecutingAssembly().Location);tray.Icon=Icon;tray.Text="Hermes Connector";tray.Visible=true;tray.DoubleClick+=(s,e)=>ShowMain();tray.BalloonTipTitle="Hermes Connector";tray.BalloonTipText="Работает в области уведомлений. Двойной щелчок открывает окно.";
   connectedTrayIcon=MakeConnectedTrayIcon(Icon);
   ContextMenuStrip menu=new ContextMenuStrip();menu.Items.Add("Открыть",null,(s,e)=>ShowMain());
   trayToggle=new ToolStripMenuItem("Подключить");trayToggle.Click+=async (s,e)=>{if(running||enrolling||revocationPending)await DisconnectAsync();else await StartOrEnrollAsync();};menu.Items.Add(trayToggle);
   gatewayMenu=new ToolStripMenuItem("Сервер МОСТ");
   foreach(string mode in new[]{"auto","gr1","gr2"}){
    string selected=mode;
    string label=mode=="auto"?"Автоматически: GR1 → GR2":mode=="gr1"?"Только GR1 (DE2)":"Только GR2 (LV1)";
    ToolStripMenuItem item=new ToolStripMenuItem(label){Tag=selected};
    item.Click+=(sender,e)=>SetGatewayMode(selected);
    gatewayMenu.DropDownItems.Add(item);
   }
   menu.Items.Add(gatewayMenu);
   modeMenu=new ToolStripMenuItem("Режим работы");
   modeMenu.DropDownItems.Add("Временная поддержка",null,(sender,e)=>SwitchMode(ConnectorMode.Support));
   modeMenu.DropDownItems.Add("Постоянный агент",null,(sender,e)=>SwitchMode(ConnectorMode.Resident));
   menu.Items.Add(modeMenu);
   pinMenu=new ToolStripMenuItem("Изменить PIN доступа к настройкам");
   pinMenu.Click+=(sender,e)=>ChangeResidentPin();menu.Items.Add(pinMenu);
   elevateMenu=new ToolStripMenuItem("Перезапустить с правами администратора");
   elevateMenu.Click+=(sender,e)=>RestartAsAdministrator();
   menu.Items.Add(elevateMenu);
   disableStartupMenu=new ToolStripMenuItem("Отключить автозапуск");
   disableStartupMenu.Click+=(sender,e)=>DisableStartupLocally();
   menu.Items.Add(disableStartupMenu);
   codeMenu=new ToolStripMenuItem("Код МОСТ");codeMenu.Visible=false;
   codeMenu.Click+=(sender,e)=>{if(!String.IsNullOrEmpty(activeMostCode))Clipboard.SetText(activeMostCode);};
   menu.Items.Add(codeMenu);
   recoverMenu=new ToolStripMenuItem("Аварийный переход на GR2 (DE2 недоступен)");
   recoverMenu.Click+=async (sender,e)=>await RecoverFromDeadGateAsync();
   menu.Items.Add(recoverMenu);
   menu.Items.Add("Выход",null,async (s,e)=>await ExitWithRevokeAsync());tray.ContextMenuStrip=menu;
   // Automatic updates only while remote support is disconnected. Signed manifest required.
   updateTimer.Interval=6*60*60*1000;
   updateTimer.Tick+=async (s,e)=>await CheckAndInstallUpdateAsync(true);
   updateTimer.Start();
   Shown+=async (s,e)=>{
    if(resumeAfterAutoUpdate&&preferences.Mode==ConnectorMode.Resident&&WindowsStartup.Enabled()){
     try{WindowsStartup.Enable(System.Reflection.Assembly.GetExecutingAssembly().Location);}
     catch(Exception ex){Status("Не удалось обновить автозапуск после установки: "+ex.Message);}
    }
    if(preferences.Mode==ConnectorMode.Resident&&(WindowsStartup.Enabled()||launchResident)){
     Hide();if(!running&&!enrolling)await StartOrEnrollAsync();
    }else if(resumeAfterElevation&&!running&&!enrolling){
     await StartOrEnrollAsync();
    }
    await CheckAndInstallUpdateAsync(true);
   };
   heartbeat.Interval=2000;heartbeat.Tick+=async (s,e)=>{if(tickBusy)return;tickBusy=true;try{await TickAsync();}finally{tickBusy=false;}};heartbeat.Start();
   LoadSettings();RestorePreferences();actionLog.Text=journal.Tail();EnsureDesktopShortcut();FormClosing+=(s,e)=>{if(!quitting){e.Cancel=true;Hide();}else{StopBridge();tray.Visible=false;tray.Dispose();if(connectedTrayIcon!=null)connectedTrayIcon.Dispose();}};
  }
  async System.Threading.Tasks.Task CheckAndInstallUpdateAsync(bool automatic){
   // A live support/resident tunnel is NOT a reason to block updates.
   // The updater pauses it only after the new binary has passed SHA256 checks.
   if(!AutoUpdatePolicy.CanUpdate(quitting,updating,enrolling,revoking,revocationPending)){
    if(!automatic)Status("Обновление будет проверено после завершения регистрации или отзыва МОСТ.");
    return;
   }
   updating=true;updates.Enabled=false;updates.Text="Проверка обновления…";
   try{
    GitHubUpdater.Release manifest=await GitHubUpdater.CheckAsync();
    updateAvailable=manifest!=null;
    if(manifest==null){if(!automatic)Status("Версия Гермес Коннектора актуальна.");return;}
    if(automatic){
     string failedPath=Path.Combine(root,"last-failed-auto-update.txt");
     var candidate=Array.Find(manifest.assets,a=>a!=null&&a.name=="HermesBridge.exe");
     if(candidate!=null&&File.Exists(failedPath)&&
        AutoUpdatePolicy.IsQuarantined(candidate.digest.Substring(7),File.ReadAllText(failedPath),DateTime.UtcNow)){
      Status("Предыдущее автообновление этого выпуска не удалось; отложено на 24 часа.");return;
     }
    }
    if(!automatic&&MessageBox.Show("Установить обновление "+manifest.tagName+
      "? Текущий туннель кратко прервётся, после установки соединение восстановится автоматически.",
      "Гермес Коннектор",MessageBoxButtons.YesNo,MessageBoxIcon.Question,
      MessageBoxDefaultButton.Button1)!=DialogResult.Yes)return;
    updates.Text="Загрузка и проверка…";
    // Download never interrupts the approved session. Fail closed if digest
    // is absent/mismatched, or the GitHub asset URL is not canonical HTTPS.
    string staged=await GitHubUpdater.StageAsync(manifest,Path.Combine(root,"updates"));
    if(!AutoUpdatePolicy.CanUpdate(quitting,false,enrolling,revoking,revocationPending))return;
    bool reconnect=AutoUpdatePolicy.ResumeAfterSwap(running,preferences.Mode==ConnectorMode.Resident);
    // Launch the rollback-capable helper first. After it starts we may pause
    // only the LOCAL socket and ssh.exe, preserving Gate approval and DPAPI.
    GitHubUpdater.Apply(manifest,staged,reconnect);
    LogAction("Автообновление подготовлено: "+manifest.tagName+". Текущий билет МОСТ сохранён.");
    StopBridge();quitting=true;Close();
   }catch(Exception ex){
    LogAction("Автообновление не применено: "+ex.GetType().Name+" "+ex.Message);
    if(!automatic)MessageBox.Show("Не удалось обновить: "+ex.Message,"Гермес Коннектор",MessageBoxButtons.OK,MessageBoxIcon.Warning);
    else Status("Проверка обновления не удалась; работаю с прежней версией.");
   }finally{
    updating=false;updates.Enabled=true;
    if(!quitting){updates.Text=updateAvailable?"Обновить":"Проверить";updates.LinkColor=updateAvailable?Color.FromArgb(36,133,78):blue;}
   }
  }
  async Task UninstallConnectorAsync(){
   if(MessageBox.Show("Окончательно удалить Connector и его локальные ключи, настройки, обновления и ярлык?\n\nТуннель будет остановлен, серверное разрешение должно быть отозвано до удаления.","Удаление Hermes Connector",MessageBoxButtons.YesNo,MessageBoxIcon.Warning)!=DialogResult.Yes)return;
   try{
    string exe=System.Reflection.Assembly.GetExecutingAssembly().Location;
    string desktop=Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
    string link=Path.Combine(desktop,"Hermes Connector.lnk");
    string expectedRoot=Path.GetFullPath(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"HermesBridge"));
    if(!String.Equals(Path.GetFullPath(root).TrimEnd('\\'),expectedRoot.TrimEnd('\\'),StringComparison.OrdinalIgnoreCase))throw new InvalidOperationException("Неправильная папка приложения");
    if(!await EnsureRevokedAsync())throw new InvalidOperationException("Gate не подтвердил отзыв доступа. Повтори после восстановления связи.");
    if(WindowsStartup.Enabled())WindowsStartup.Disable();
    int ownPid=Process.GetCurrentProcess().Id;
    // Detached helper waits for this process to EXIT before deleting its locked executable.
    // Remove-Item deletes directly, NOT via the Recycle Bin; never empty the whole Bin.
    string script=""+
     "$pidToWait="+ownPid+";"+
     "for($n=0;$n -lt 120;$n++){if(-not (Get-Process -Id $pidToWait -ErrorAction SilentlyContinue)){break};Start-Sleep -Milliseconds 500};"+
     "if(Get-Process -Id $pidToWait -ErrorAction SilentlyContinue){exit 4};"+
     "$targets=@("+PsLiteral(exe)+","+PsLiteral(link)+","+PsLiteral(expectedRoot)+");"+
     "foreach($target in $targets){for($retry=0;$retry -lt 10;$retry++){try{Remove-Item -LiteralPath $target -Recurse -Force -ErrorAction Stop;break}catch{Start-Sleep -Milliseconds 500}}}";
    string encoded=Convert.ToBase64String(Encoding.Unicode.GetBytes(script));
    Process.Start(new ProcessStartInfo("powershell.exe","-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand "+encoded){UseShellExecute=false,CreateNoWindow=true});
    quitting=true;Close();
   }catch(Exception ex){MessageBox.Show("Не удалось запустить удаление: "+ex.Message,"Hermes Connector",MessageBoxButtons.OK,MessageBoxIcon.Warning);}
  }
  static string PsLiteral(string text){return "'"+text.Replace("'","''")+"'";}
  void AddLine(string title,TextBox t,ref int y){advanced.Controls.Add(new Label(){Text=title,Left=26,Top=y+4,Width=240});t.Left=270;t.Top=y;t.Width=189;advanced.Controls.Add(t);y+=34;}
  void EnsureDesktopShortcut(){
   try {
    string desktop=Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
    if(!String.IsNullOrWhiteSpace(desktop)){string exe=System.Reflection.Assembly.GetExecutingAssembly().Location;string appdir=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"HermesBridge");if(!File.Exists(Path.Combine(desktop,"Hermes Connector.lnk"))||String.Equals(Path.GetDirectoryName(exe),appdir,StringComparison.OrdinalIgnoreCase))CreateDesktopShortcut(true);}
   }catch(Exception){} // Shortcut failure must not prevent launching the app.
  }
  void CreateDesktopShortcut(){CreateDesktopShortcut(false);}
  void CreateDesktopShortcut(bool silent){
   try{
    string exe=System.Reflection.Assembly.GetExecutingAssembly().Location;
    string desktop=Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
    if(String.IsNullOrWhiteSpace(desktop))throw new InvalidOperationException("Не найден рабочий стол");
    string link=Path.Combine(desktop,"Hermes Connector.lnk");
    Type shellType=Type.GetTypeFromProgID("WScript.Shell");
    if(shellType==null)throw new InvalidOperationException("Нет поддержки Windows Shortcut");
    object shell=Activator.CreateInstance(shellType);
    try{
     object obj=shellType.InvokeMember("CreateShortcut",System.Reflection.BindingFlags.InvokeMethod,null,shell,new object[]{link});
     try{
      Type t=obj.GetType();var flags=System.Reflection.BindingFlags.SetProperty;
      t.InvokeMember("TargetPath",flags,null,obj,new object[]{exe});
      t.InvokeMember("WorkingDirectory",flags,null,obj,new object[]{Path.GetDirectoryName(exe)});
      t.InvokeMember("IconLocation",flags,null,obj,new object[]{exe+",0"});
      t.InvokeMember("Description",flags,null,obj,new object[]{"Hermes Connector — доступ с разрешения"});
      t.InvokeMember("Save",System.Reflection.BindingFlags.InvokeMethod,null,obj,new object[]{});
     }finally{System.Runtime.InteropServices.Marshal.FinalReleaseComObject(obj);}
    }finally{System.Runtime.InteropServices.Marshal.FinalReleaseComObject(shell);}
    if(!silent)Status("Ярлык создан на рабочем столе.");
   }catch(Exception ex){if(!silent)MessageBox.Show("Не удалось создать ярлык: "+ex.Message,"Hermes Connector",MessageBoxButtons.OK,MessageBoxIcon.Warning);}
  }
  static Icon MakeConnectedTrayIcon(Icon source){
   // Draw at tray resolution so the indicator remains legible at 16px.
   using(Bitmap bitmap=new Bitmap(32,32))using(Graphics g=Graphics.FromImage(bitmap)){
    g.Clear(Color.Transparent);g.DrawIcon(source,new Rectangle(0,0,32,32));
    using(Brush rim=new SolidBrush(Color.White))g.FillEllipse(rim,17,17,15,15);
    using(Brush dot=new SolidBrush(Color.FromArgb(34,197,94)))g.FillEllipse(dot,19,19,11,11);
    IntPtr hicon=bitmap.GetHicon();
    try{using(Icon temp=Icon.FromHandle(hicon))return (Icon)temp.Clone();}
    finally{DestroyIcon(hicon);}
   }
  }
  [System.Runtime.InteropServices.DllImport("user32.dll")]static extern bool DestroyIcon(IntPtr handle);
  void ShowMain(){
   if(preferences.Mode==ConnectorMode.Resident){
    if(!UnlockResidentToSupport())return;
   }
   Show();WindowState=FormWindowState.Normal;Activate();
  }
  bool EnsureResidentPin(){
   try{
    bool first=residentPin.InitializeDefault();
    if(first)MessageBox.Show("Первоначальный PIN управления треем: 1111. " +
      "Этот PIN слабый и подходит только для начальной настройки. " +
      "Сразу измените его в меню трея «Изменить PIN». " +
      "Остановка удалённой поддержки остаётся доступной без PIN.",
      "Настройка PIN",MessageBoxButtons.OK,MessageBoxIcon.Warning);
    return true;
   }catch(Exception ex){
    MessageBox.Show("Не удалось подготовить PIN-хранилище: "+ex.Message,
      "PIN постоянного агента",MessageBoxButtons.OK,MessageBoxIcon.Error);return false;
   }
  }
  bool AuthorizeResidentSettings(){
   if(preferences.Mode!=ConnectorMode.Resident)return true;
   if(!EnsureResidentPin())return false;
   return ResidentPinDialog.Authenticate(this,residentPin);
  }
  void ChangeResidentPin(){
   if(!EnsureResidentPin())return;
   if(ResidentPinDialog.Change(this,residentPin))LogAction("PIN управления треем изменён текущим пользователем.");
  }
  bool UnlockResidentToSupport(){
   if(preferences.Mode!=ConnectorMode.Resident)return true;
   if(!AuthorizeResidentSettings())return false;
   try{if(WindowsStartup.Enabled())WindowsStartup.Disable();}
   catch(Exception ex){MessageBox.Show("Не удалось отключить автозапуск: "+ex.Message,
      "Возврат к поддержке",MessageBoxButtons.OK,MessageBoxIcon.Warning);return false;}
   preferences.Mode=ConnectorMode.Support;
   preferences.AutoDisconnect=false;
   loadingPrefs=true;try{autoDisconnect.Checked=false;}finally{loadingPrefs=false;}
   UpdateModeMenu();UpdateDeadline();SavePreferences();
   Status("Открыта поддержка. Автозапуск выключен; текущий МОСТ остаётся активным до ручного отключения.");
   return true;
  }
  void RestorePreferences(){
   loadingPrefs=true;
   try{
    preferences=ConnectorPreferences.Load(PrefsPath);
    if(preferences.Mode==ConnectorMode.Resident&&!WindowsStartup.Enabled())preferences.Mode=ConnectorMode.Support;
    autoDisconnect.Checked=preferences.AutoDisconnect;
    autoDisconnect.Enabled=preferences.Mode==ConnectorMode.Support;
    ttl.Value=preferences.DisconnectMinutes;
    ttl.Enabled=preferences.Mode==ConnectorMode.Support&&preferences.AutoDisconnect;
    SetLogExpanded(preferences.LogExpanded,false);
    UpdateModeMenu();
   }finally{loadingPrefs=false;}
  }
  void SavePreferences(){
   if(loadingPrefs)return;
   preferences.AutoDisconnect=autoDisconnect.Checked&&preferences.Mode==ConnectorMode.Support;
   preferences.DisconnectMinutes=(int)ttl.Value;
   try{preferences.Save(PrefsPath);}catch(Exception ex){LogAction("Сохранение настроек: "+ex.Message);}
  }
  void SetLogExpanded(bool expanded,bool save=true){
   preferences.LogExpanded=expanded;
   bool visible=expanded&&preferences.Mode==ConnectorMode.Support;
   logTitle.Visible=visible;actionLog.Visible=visible;copyLog.Visible=visible;
   logToggle.Text=expanded?"Журнал действий  ◂":"Журнал действий  ▸";
   Width=expanded?900:495;
   if(save)SavePreferences();
  }
  void UpdateDeadline(){
   deadline=preferences.Mode==ConnectorMode.Support&&autoDisconnect.Checked?
    sessionStarted.AddMinutes((double)ttl.Value):DateTime.MaxValue;
  }
  void DisableStartupLocally(){
   if(preferences.Mode!=ConnectorMode.Resident)return;
   if(!AuthorizeResidentSettings())return;
   if(MessageBox.Show("Выключить автоматический запуск Гермес Коннектора при следующем входе в Windows?\n\n"+
      "Текущий SSH-туннель не прерывается. Эта операция НЕ является отзывом разрешения на сервере. " +
      "Для полного прекращения доступа нужно отдельно завершить сеанс и дождаться подтверждения от Gate.",
      "Отключение постоянного режима",MessageBoxButtons.YesNo,MessageBoxIcon.Warning,MessageBoxDefaultButton.Button2)!=DialogResult.Yes)return;
   try{WindowsStartup.Disable();}
   catch(Exception ex){Status("Не удалось выключить автозапуск: "+ex.Message);return;}
   UpdateModeMenu();
   Status("Автозапуск выключен. Текущее серверное разрешение не изменено.");
  }
  void UpdateModeMenu(){
   if(disableStartupMenu!=null)disableStartupMenu.Visible=preferences.Mode==ConnectorMode.Resident&&WindowsStartup.Enabled();
   if(modeMenu!=null){
    modeMenu.DropDownItems[0].Text=(preferences.Mode==ConnectorMode.Support?"✓ ":"")+"Временная поддержка";
    modeMenu.DropDownItems[1].Text=(preferences.Mode==ConnectorMode.Resident?"✓ ":"")+"Постоянный агент";
   }
   autoDisconnect.Visible=preferences.Mode==ConnectorMode.Support;
   ttl.Visible=preferences.Mode==ConnectorMode.Support;
   autoDisconnect.Enabled=preferences.Mode==ConnectorMode.Support;
   bool support=preferences.Mode==ConnectorMode.Support;
   shortcut.Visible=support;closeApp.Visible=support;uninstall.Visible=support;
   installSsh.Visible=support&&!File.Exists(Ssh);sshServerInstall.Visible=support;
   sshCheck.Visible=support;updates.Visible=support;emergencyLink.Visible=support;
   logToggle.Visible=support;
   elevateLink.Visible=support&&!ElevationSupport.IsElevated();
   if(elevateMenu!=null)elevateMenu.Visible=!ElevationSupport.IsElevated();
   logTitle.Visible=support&&preferences.LogExpanded;
   actionLog.Visible=support&&preferences.LogExpanded;
   copyLog.Visible=support&&preferences.LogExpanded;
  }
  bool RestartAsAdministrator(){
   if(elevating||quitting)return false;
   if(!AuthorizeResidentSettings())return false;
   if(ElevationSupport.IsElevated()){
    Status("Коннектор уже запущен с правами администратора.");return false;
   }
   if(updating||revoking||revocationPending){
    Status("Сначала заверши обновление или отзыв прежней регистрации МОСТ.");return false;
   }
   TokenElevationKind kind;
   try{kind=ElevationSupport.CurrentTokenKind();}
   catch(Exception ex){Error("Не удалось определить тип Windows-токена: "+ex.Message);return false;}
   if(!ElevationSupport.CanElevateSameUser(false,kind)){
    MessageBox.Show("У текущей учётной записи нет доступного повышенного токена. " +
      "Windows может потребовать пароль ДРУГОГО администратора. Это будет другой пользователь, " +
      "поэтому регистрация МОСТ и пользовательский сеанс Alex не будут перенесены. " +
      "Диагностика в обычных правах остаётся доступной.",
      "Требуются права текущего пользователя",MessageBoxButtons.OK,MessageBoxIcon.Information);
    return false;
   }
   bool active=running||enrolling;
   string question="Windows откроет UAC для этой же учётной записи. " +
     "Коннектор после подтверждения запустится с правами администратора, " +
     "не меняя владельца регистрации МОСТ.\n\n"+
     (active?"Текущий SSH-туннель кратко прервётся и будет восстановлен с прежним разрешением. " +
       "Разрешение на GR2 НЕ отзывается и не требуется новый код МОСТ.\n\n":"")+
     "При отмене UAC существующий процесс продолжит работу. " +
     "Автозапуск после следующего входа в Windows останется с ОБЫЧНЫМИ правами.\n\nПродолжить?";
   if(MessageBox.Show(question,"Повышение прав Hermes Connector",MessageBoxButtons.YesNo,
      MessageBoxIcon.Warning,MessageBoxDefaultButton.Button2)!=DialogResult.Yes)return false;
   elevating=true;
   try{
    ElevationSupport.StartElevated(System.Reflection.Assembly.GetExecutingAssembly().Location,
      ElevationSupport.CurrentSid(),preferences.Mode==ConnectorMode.Resident);
    // Only AFTER Windows accepts UAC, release the existing per-user mutex.
    // Do NOT call DisconnectAsync/EnsureRevokedAsync: the ticket stays valid.
    LogAction("Подтверждён переход к повышенному экземпляру. Старое разрешение МОСТ сохранено.");
    StopBridge();quitting=true;Close();return true;
   }catch(System.ComponentModel.Win32Exception ex){
    Status(ex.NativeErrorCode==1223?"Запрос UAC отменён. Текущий туннель не прерван.":
      "Windows не разрешила повышение прав: "+ex.Message);
    return false;
   }catch(Exception ex){Error("Перезапуск с правами администратора не выполнен: "+ex.Message);return false;}
   finally{elevating=false;}
  }
  async void SwitchMode(ConnectorMode next){
   if(next==preferences.Mode)return;
   if(preferences.Mode==ConnectorMode.Resident&&next==ConnectorMode.Support){ShowMain();return;}
   if(running||enrolling||revoking||revocationPending||File.Exists(Path.Combine(root,"approval-ticket"))){
    Status("Сначала заверши текущее разрешение МОСТ; изменение режима требует нового подтверждения на сервере.");return;
   }
   bool requestAdminForCurrentSession=false;
   if(next==ConnectorMode.Resident&&!ElevationSupport.IsElevated()){
    DialogResult option=MessageBox.Show("Постоянный агент может работать с обычными правами. " +
      "Для расширенных административных действий можно дополнительно повысить права ТОЛЬКО текущего сеанса.\n\n"+
      "Да — запросить Windows UAC после включения автозапуска.\n"+
      "Нет — оставить обычные права (рекомендуется для постоянной работы).\n"+
      "Отмена — не менять режим.\n\n"+
      "После входа в Windows автозапуск будет без повышения прав.",
      "Права постоянного агента",MessageBoxButtons.YesNoCancel,MessageBoxIcon.Question,
      MessageBoxDefaultButton.Button2);
    if(option==DialogResult.Cancel)return;
    requestAdminForCurrentSession=option==DialogResult.Yes;
   }
   if(next==ConnectorMode.Resident){
    if(!EnsureResidentPin())return;
    string message="Включить постоянный агент для текущего пользователя Windows?\n\n"+
     "Коннектор будет запускаться после входа в этот профиль и восстанавливать туннель. " +
     "SSH-подключение не даёт бессрочных прав само по себе: постоянное разрешение отдельно утверждается на Gate. " +
     "В трее останутся иконка и пункт «Выход».\n\nВключить автозапуск?";
    if(MessageBox.Show(message,"Постоянный Hermes Connector",MessageBoxButtons.YesNo,MessageBoxIcon.Question,MessageBoxDefaultButton.Button2)!=DialogResult.Yes)return;
    try{WindowsStartup.Enable(System.Reflection.Assembly.GetExecutingAssembly().Location);}
    catch(Exception ex){Error("Не удалось включить автозапуск: "+ex.Message);return;}
   }else{
    try{WindowsStartup.Disable();}
    catch(Exception ex){Error("Не удалось выключить автозапуск: "+ex.Message);return;}
   }
   preferences.Mode=next;
   if(next==ConnectorMode.Resident)autoDisconnect.Checked=false;
   UpdateModeMenu();UpdateDeadline();SavePreferences();
   Status(next==ConnectorMode.Resident?"Постоянный режим включён: автозапуск при входе Windows.":"Временная поддержка: автозапуск выключен.");
   if(next==ConnectorMode.Resident){
    if(requestAdminForCurrentSession&&RestartAsAdministrator())return;
    Hide();
    if(!running&&!enrolling)await StartOrEnrollAsync();
   }
  }
  void Status(string value){
   if(state==null)return;
   bool processAlive=false;
   try{processAlive=tunnel!=null&&!tunnel.HasExited;}catch{}
   state.Text=running&&processAlive&&forwardConfirmed&&userAgent!=null?"Туннель открыт":enrolling?"Ожидаем разрешение":running?"Подключение…":"Доступ отключён";
   state.ForeColor=running&&processAlive&&forwardConfirmed&&userAgent!=null?Color.FromArgb(22,101,52):running?blue:ink;
   connectionInfo.Text=value;
   deviceInfo.Text="ПК: "+Environment.MachineName+" · IPv4: "+(EnrollmentClient.LocalIPv4()??"не определён");mostCode.Text=activeMostCode;
   if(codeMenu!=null){codeMenu.Visible=!String.IsNullOrWhiteSpace(activeMostCode);codeMenu.Text="Код МОСТ: "+activeMostCode+" — копировать";}
   if(!String.IsNullOrWhiteSpace(activeMostCode)&&value.StartsWith("Код МОСТ: ",StringComparison.Ordinal)&&announcedCode!=activeMostCode){
    announcedCode=activeMostCode;
    tray.BalloonTipTitle="Нужно подтверждение МОСТ";
    tray.BalloonTipText="Код "+activeMostCode+". Передай его оператору для разрешения подключения.";
    if(tray.Visible)tray.ShowBalloonTip(5000);
   }
   expiryInfo.Text=running&&preferences.Mode==ConnectorMode.Support&&autoDisconnect.Checked?"Отключение: "+deadline.ToLocalTime().ToString("HH:mm"):"Автоотключение выключено";
   bool connected=running&&processAlive&&forwardConfirmed&&userAgent!=null;
   start.Visible=preferences.Mode==ConnectorMode.Support&&!running&&!enrolling&&!revoking&&!revocationPending;
   stop.Visible=preferences.Mode==ConnectorMode.Support&&(running||enrolling||revoking||revocationPending);start.Enabled=!running&&!enrolling&&!revoking&&!revocationPending;stop.Enabled=(running||enrolling||revocationPending)&&!revoking;
   if(trayToggle!=null){trayToggle.Text=running||enrolling||revocationPending?"Отключить":"Подключить";trayToggle.Enabled=true;}
   if(tray.Visible){tray.Icon=connected&&connectedTrayIcon!=null?connectedTrayIcon:Icon;tray.Text=connected?"Hermes Connector — туннель открыт":enrolling?"Hermes Connector — ожидание":"Hermes Connector — отключён";}
   UpdateSshState();LogAction(value);
  }
  void LogAction(string message){
   if(String.IsNullOrWhiteSpace(message)||actionLog.IsDisposed)return;
   string sanitized=ActivityJournal.Sanitize(message);
   if(String.IsNullOrWhiteSpace(sanitized))return;
   try{journal.Append(message);}catch(IOException){}catch(UnauthorizedAccessException){}
   if(actionLog.TextLength>24000)actionLog.Text=actionLog.Text.Substring(actionLog.TextLength-12000);
   actionLog.AppendText(DateTime.Now.ToString("HH:mm:ss")+"  "+sanitized+Environment.NewLine);
  }
  void UpdateSshState(){
   bool installed=File.Exists(Ssh);
   if(installed&&sshVersion==null){
    sshVersion="доступен";
    try{
     var psi=new ProcessStartInfo(Ssh,"-V"){UseShellExecute=false,CreateNoWindow=true,RedirectStandardError=true};
     using(var proc=Process.Start(psi)){
      string line=proc.StandardError.ReadLine();
      if(!proc.WaitForExit(2500)){proc.Kill();}else if(!String.IsNullOrWhiteSpace(line)){
       var match=System.Text.RegularExpressions.Regex.Match(line,@"OpenSSH[_ ](?:for_Windows_)?([0-9.]+p[0-9]+)");
       sshVersion=match.Success?match.Groups[1].Value:"доступен";
      }
     }
    }catch{}
   }
   using(var id=WindowsIdentity.GetCurrent()){
    var principal=new WindowsPrincipal(id);
    bool isAdmin=principal.IsInRole(WindowsBuiltInRole.Administrator);
    sshInfo.Text="Исполнение: "+id.Name+(isAdmin?" [администратор]":" [обычные права]")+"\nSSH: "+(installed?sshVersion:"клиент не установлен");
    elevateLink.Visible=preferences.Mode==ConnectorMode.Support&&!isAdmin;
    if(elevateMenu!=null)elevateMenu.Visible=!isAdmin;
   }
   installSsh.Visible=preferences.Mode==ConnectorMode.Support&&!installed&&SshServerHealth.SupportsWindowsCapability();
   installSsh.Text="Установить SSH Client";
   sshServerInstall.Visible=preferences.Mode==ConnectorMode.Support&&SshServerHealth.SupportsWindowsCapability();
   sshCheck.Visible=preferences.Mode==ConnectorMode.Support&&installed;sshCheck.Text="Пользователь";sshCheck.Enabled=true;
  }
  static string ServerLabel(SshServerState state){
   switch(state){
    case SshServerState.ServerMissing: return "не установлен";
    case SshServerState.ServerStopped: return "остановлен";
    case SshServerState.PortClosed: return "порт 22 недоступен";
    case SshServerState.WrongProtocol: return "ошибка SSH-протокола";
    case SshServerState.Ready: return "порт 22 работает; вход Гермеса не проверен";
    case SshServerState.Unknown: return "ошибка проверки";
    default: return "не проверен";
   }
  }
  async Task RefreshSshHealthAsync(bool notify){
   if(sshHealthBusy)return;
   sshHealthBusy=true;UpdateSshState();
   try {
    sshHealth=await Task.Run(()=>SshServerHealth.Probe(Ssh));
    if(notify){
     Status(sshHealth.Explanation);
     if(!sshHealth.Ready && MessageBox.Show(sshHealth.Explanation+".\n\nОткрыть официальную инструкцию Microsoft по установке и настройке OpenSSH Server?", "OpenSSH Server", MessageBoxButtons.YesNo, MessageBoxIcon.Information)==DialogResult.Yes)
      Process.Start(new ProcessStartInfo("https://learn.microsoft.com/ru-ru/windows-server/administration/openssh/openssh_install_firstuse"){UseShellExecute=true});
    }
   }catch(Exception ex){sshHealth=null;if(notify)Status("Проверка OpenSSH не удалась: "+ex.Message);}
   finally{sshHealthBusy=false;UpdateSshState();}
  }
  async Task<bool> InstallOpenSshAsync(SshComponent component){
   if(sshHealthBusy)return false;
   string name=component==SshComponent.Client?"OpenSSH Client":"OpenSSH Server";
   if(MessageBox.Show("Установить "+name+" штатными средствами Windows?\n\n"+
      "Может понадобиться Windows Update, доступ к источнику компонентов и подтверждение UAC. " +
      "Внимание: Windows может при установке SSH Server создать правило входящего TCP/22. " +
      "Коннектор отключит только новое правило и не запустит службу, но во время установки возможно краткое изменение правил. " +
      "Уже работающие SSH-службы и настройки не изменяем.",
      "Hermes Connector — компоненты SSH",MessageBoxButtons.YesNo,MessageBoxIcon.Question,MessageBoxDefaultButton.Button2)!=DialogResult.Yes)return false;
   sshHealthBusy=true;
   try{
    Status("Подготовка "+name+"…");
    int code=await OpenSshComponents.InstallAsync(component);
    if(code!=0){Status("Установка "+name+" завершилась с ошибкой "+code+". Проверь Windows Update / WSUS.");return false;}
    sshVersion=null;UpdateSshState();
    Status(name+" установлен. Если SSH Server был новым, его входящее правило отключено, служба не запускается автоматически.");
    return true;
   }catch(System.ComponentModel.Win32Exception ex){Status("Запрос прав администратора отклонён или недоступен: "+ex.Message);return false;}
   catch(Exception ex){Status("Ошибка установки "+name+": "+ex.Message);return false;}
   finally{sshHealthBusy=false;UpdateSshState();}
  }
  async Task<bool> EnsureOpenSshClientAsync(){
   if(File.Exists(Ssh))return true;
   Status("OpenSSH Client не найден. Коннектор предложит установку.");
   if(!await InstallOpenSshAsync(SshComponent.Client))return false;
   return File.Exists(Ssh);
  }
  Uri EnrollmentEndpoint {get{return GatewayEndpoints.Stored(enrollmentApi,host.Text.Trim());}}
  void UpdateGatewayMenu(){
   if(gatewayMenu==null)return;
   foreach(ToolStripMenuItem item in gatewayMenu.DropDownItems)item.Checked=String.Equals(item.Tag as string,gatewayMode,StringComparison.Ordinal);
  }
  async Task RecoverFromDeadGateAsync(){
   if(!AuthorizeResidentSettings())return;
   if(running||enrolling||revoking||updating){
    MessageBox.Show("Аварийный переход возможен только после остановки локального туннеля и завершения текущих операций.","МОСТ",MessageBoxButtons.OK,MessageBoxIcon.Warning);return;
   }
   if(tunnel!=null){try{if(!tunnel.HasExited){MessageBox.Show("Локальный SSH-процесс ещё работает. Сначала останови туннель.","МОСТ");return;}}catch{return;}}
   bool hasState=File.Exists(Path.Combine(root,"approval-ticket"))||!String.IsNullOrWhiteSpace(slot.Text)||File.Exists(Key);
   if(!hasState){SetGatewayMode("gr2");return;}
   string warning="Аварийный переход на GR2 (Латвия).\n\n"+
    "Старый DE2 не подтвердил отзыв разрешения. Это НЕ означает, что разрешение на DE2 закрыто.\n\n"+
    "Старые ключи, билет и настройки будут сохранены в защищённой папке восстановления Windows-профиля. " +
    "Будет создан НОВЫЙ SSH-ключ и потребуется отдельное подтверждение GR2.\n\n"+
    "Действительно перейти на GR2?";
   if(MessageBox.Show(warning,"Аварийный МОСТ",MessageBoxButtons.YesNo,MessageBoxIcon.Warning,MessageBoxDefaultButton.Button2)!=DialogResult.Yes)return;
   try{
    string archive=EmergencyRecovery.ArchiveAndRotate(root,"gr2");
    revocationPending=false;running=false;enrolling=false;cancelEnrollment=false;
    host.Text="";slot.Text="";port.Text="22471";known.Text=Known;activeMostCode="";
    gatewayMode="gr2";enrollmentApi=GatewayEndpoints.Backup;
    SaveSettings();UpdateGatewayMenu();
    Status("Старое разрешение DE2 НЕ отозвано. Ключ и билет сохранены: "+archive+". Новый ключ GR2 создаётся при подключении.");

   }catch(Exception ex){MessageBox.Show("Аварийный переход не выполнен: "+ex.Message,"МОСТ",MessageBoxButtons.OK,MessageBoxIcon.Error);}
  }
  void SetGatewayMode(string value){
   if(!AuthorizeResidentSettings())return;
   if(running||enrolling||revoking||revocationPending||File.Exists(Path.Combine(root,"approval-ticket"))||(!String.IsNullOrWhiteSpace(slot.Text)&&File.Exists(Known))){
    Status("Сначала заверши разрешение и дождись подтверждённого отзыва на текущем Gate.");return;
   }
   if(value!="auto"&&value!="gr1"&&value!="gr2")return;
   gatewayMode=value;
   enrollmentApi=value=="gr2"?GatewayEndpoints.Backup:GatewayEndpoints.Primary;
   SaveSettings();UpdateGatewayMenu();
   Status("Шлюз МОСТ: "+(value=="auto"?"автоматически GR1 → GR2":value.ToUpperInvariant()));
  }
  void LoadSettings(){
   device.Text=Environment.MachineName;host.Text="";port.Text="22471";slot.Text="";known.Text=Known;ttl.Value=60;
   gatewayMode="auto";enrollmentApi=null;
   if(File.Exists(Config)){foreach(string line in File.ReadAllLines(Config,Encoding.UTF8)){
    int i=line.IndexOf('=');if(i<1)continue;string name=line.Substring(0,i),value=line.Substring(i+1);
    if(name=="device")device.Text=value;if(name=="host")host.Text=value;if(name=="port")port.Text=value;if(name=="slot")slot.Text=value;
    if(name=="gateway_mode"&&(value=="auto"||value=="gr1"||value=="gr2"))gatewayMode=value;
    if(name=="enrollment_api")enrollmentApi=value;
    int n;if(name=="ttl"&&int.TryParse(value,out n))ttl.Value=Math.Max(5,Math.Min(1440,n));
   }}
   // Pre-GR versions wrote no broker URL. A pending old ticket belongs to DE2.
   if(String.IsNullOrWhiteSpace(enrollmentApi)&&File.Exists(Path.Combine(root,"approval-ticket"))&&String.IsNullOrWhiteSpace(host.Text))enrollmentApi=GatewayEndpoints.Legacy;
   enrollmentApi=GatewayEndpoints.Stored(enrollmentApi,host.Text.Trim()).AbsoluteUri;
   UpdateGatewayMenu();
   Status("Нажми «Подключить Гермеса» для запроса доступа. Шлюз: "+gatewayMode.ToUpperInvariant()+".");
  }
  void SaveSettings(){
   if(!Valid(false))return;
   string result="device="+device.Text.Trim()+"\nhost="+host.Text.Trim()+"\nport="+port.Text.Trim()+"\nslot="+slot.Text.Trim()+"\nttl="+ttl.Value+"\ngateway_mode="+gatewayMode+"\nenrollment_api="+EnrollmentEndpoint.AbsoluteUri+"\n";
   File.WriteAllText(Config,result,Encoding.UTF8);Status("Настройки сохранены.");
  }
  bool Valid(bool strict){
   string safe="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_";
   Func<string,bool> ok=s=>s.Length>0&&s.Length<128&&s.All(c=>safe.IndexOf(c)>=0);
   int p,r;if(!ok(device.Text.Trim())){Error("Некорректное имя устройства");return false;}
   if(strict||host.Text.Trim().Length>0)if(!ok(host.Text.Trim())){Error("Некорректный домен");return false;}
   if(!int.TryParse(port.Text,out p)||p<1||p>65535){Error("Некорректный SSH-порт");return false;}
   if(strict||slot.Text.Trim().Length>0)if(!int.TryParse(slot.Text,out r)||r<1024||r>65535){Error("Некорректный обратный порт");return false;}
   return true;
  }
  void ImportProvision(){
   using(var dlg=new OpenFileDialog()){
    dlg.Filter="Hermes Bridge registration (*.bridge)|*.bridge|All files (*.*)|*.*";
    if(dlg.ShowDialog()!=DialogResult.OK)return;
    var rows=File.ReadAllLines(dlg.FileName,Encoding.UTF8);
    var values=new System.Collections.Generic.Dictionary<string,string>(StringComparer.OrdinalIgnoreCase);
    foreach(string row in rows){int i=row.IndexOf('=');if(i<1)continue;values[row.Substring(0,i).Trim()]=row.Substring(i+1).Trim();}
    string h,p,r,k;
    if(!values.TryGetValue("host",out h)||!values.TryGetValue("port",out p)||!values.TryGetValue("slot",out r)||!values.TryGetValue("hostkey",out k)){Error("Неполный файл регистрации");return;}
    if(k.IndexOf('\n')>=0||k.IndexOf('\r')>=0 || !k.StartsWith("ssh-ed25519 ")){Error("Неверный SSH host key");return;}
    host.Text=h;port.Text=p;slot.Text=r;
    if(!Valid(true))return;
    File.WriteAllText(Known,"["+h+"]:"+p+" "+k+Environment.NewLine,Encoding.ASCII);
    SaveSettings();Status("Регистрация импортирована. Проверь достоверность источника файла.");
   }
  }
  void Error(string message){MessageBox.Show(message,"Гермес Мост",MessageBoxButtons.OK,MessageBoxIcon.Warning);}
  bool EnsureKey(){
   if(File.Exists(Key))return true;
   string keygen=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),"OpenSSH","ssh-keygen.exe");
   if(!File.Exists(keygen)){Error("Требуется OpenSSH Client в Windows.");return false;}
   var psi=new ProcessStartInfo(keygen,"-q -t ed25519 -N \"\" -f \""+Key+"\"");psi.UseShellExecute=false;psi.CreateNoWindow=true;
   using(Process p=Process.Start(psi)){p.WaitForExit(15000);if(!p.HasExited){p.Kill();Error("Генерация ключа превысила 15 секунд");return false;}if(p.ExitCode!=0){Error("Не удалось создать ключ устройства");return false;}}
   return File.Exists(Key)&&File.Exists(Key+".pub");
  }
  async Task StartOrEnrollAsync(){
   if(running||enrolling||revoking||revocationPending)return;
   if(!await EnsureOpenSshClientAsync())return;
   if(!EnsureKey())return;
   if(!String.IsNullOrWhiteSpace(slot.Text)&&File.Exists(Known)&&File.Exists(Path.Combine(root,"approval-ticket"))){
    try{
     EnrollmentResult a=await EnrollmentClient.PollAsync(EnrollmentEndpoint,TicketStore.Read(Path.Combine(root,"approval-ticket")));
     if(a.status=="approved"&&EnrollmentClient.Valid(a.config)&&a.config.slot.ToString()==slot.Text.Trim()&&a.config.host==host.Text.Trim()){
      await StartBridgeAsync();return;
     }
     if(a.status=="revoked"||a.status=="expired"||a.status=="denied"){
      Status("Gate подтвердил завершение предыдущего разрешения.");ClearLocalApproval();
     }else{Status("Прежнее разрешение ещё не закрыто на Gate: "+a.status);return;}
    }catch(Exception ex){Status("Невозможно проверить ранее выданное разрешение: "+ex.Message);return;}
   }
   if(!File.Exists(Path.Combine(root,"approval-ticket"))&&!String.IsNullOrWhiteSpace(slot.Text)&&File.Exists(Known)){
    Status("Старое разрешение не имеет билета отзыва. Нужен операторский отзыв на исходном Gate.");return;
   }
   bool resumePending=File.Exists(Path.Combine(root,"approval-ticket"));
   enrolling=true;cancelEnrollment=false;int generation=++enrollmentGeneration;Status(resumePending?"Восстанавливаем прежнюю заявку МОСТ…":"Проверяем доступность GR1 и GR2…");
   try{
    Uri endpoint=resumePending?EnrollmentEndpoint:await GatewayEndpoints.ChooseAsync(gatewayMode);
    if(!resumePending){enrollmentApi=endpoint.AbsoluteUri;SaveSettings();}
    Status((resumePending?"Проверяем прежнюю заявку через ":"Отправляем заявку через ")+endpoint.Host+"…");
    while(!cancelEnrollment&&generation==enrollmentGeneration){
     EnrollmentTicket ticket=resumePending?new EnrollmentTicket{ticket=TicketStore.Read(Path.Combine(root,"approval-ticket")),code=""}:null;
     resumePending=false;
     while(ticket==null&&!cancelEnrollment&&generation==enrollmentGeneration){
     bool retry=false;
     try{ticket=await EnrollmentClient.SubmitAsync(endpoint,device.Text.Trim(),File.ReadAllText(Key+".pub").Trim(),preferences.Mode==ConnectorMode.Resident,preferences.Mode==ConnectorMode.Support&&autoDisconnect.Checked?(int)ttl.Value*60:0);}
     catch(WebException ex){
      var response=ex.Response as HttpWebResponse;
      bool transient=response!=null&&(response.StatusCode==HttpStatusCode.ServiceUnavailable||(int)response.StatusCode==429||response.StatusCode==HttpStatusCode.BadGateway||response.StatusCode==HttpStatusCode.GatewayTimeout);
      transient=transient||ex.Status==WebExceptionStatus.Timeout||ex.Status==WebExceptionStatus.ConnectFailure||ex.Status==WebExceptionStatus.NameResolutionFailure;
      if(!transient)throw;
      Status("МОСТ: сервер занят или недоступен. Повторяем запрос без нового нажатия…");
      retry=true;
     }
     if(retry)await Task.Delay(35000);
    }
    if(generation!=enrollmentGeneration||cancelEnrollment||ticket==null)return;
    TicketStore.Write(Path.Combine(root,"approval-ticket"),ticket.ticket);
    activeMostCode=ticket.code;
    if(String.IsNullOrWhiteSpace(ticket.code))Status("Прежняя заявка ещё ожидает решения на "+endpoint.Host+". Используй ранее выданный код.");
    else Status("Код МОСТ: "+ticket.code+" · Назови его при подтверждении.");
    // Reuse the same request and code until approval/rejection/expiry. Transient HTTP
    // errors must NEVER create another registration or discard this ticket.
    while(!cancelEnrollment&&generation==enrollmentGeneration){
     await Task.Delay(5000); // Poll quota is separate from POST submissions (60 requests/min/IP).
     if(cancelEnrollment||generation!=enrollmentGeneration)return;
     EnrollmentResult answer;
     try{answer=await EnrollmentClient.PollAsync(endpoint,ticket.ticket);}
     catch(WebException ex){
      var response=ex.Response as HttpWebResponse;
      if(response!=null&&(response.StatusCode==HttpStatusCode.ServiceUnavailable||(int)response.StatusCode==429||response.StatusCode==HttpStatusCode.BadGateway||response.StatusCode==HttpStatusCode.GatewayTimeout)){
       Status("Код МОСТ: "+ticket.code+" · Сервер временно занят, повторяем проверку…");continue;
      }
      if(ex.Status==WebExceptionStatus.Timeout||ex.Status==WebExceptionStatus.ConnectFailure||ex.Status==WebExceptionStatus.NameResolutionFailure){
       Status("Код МОСТ: "+ticket.code+" · Нет связи, ожидаем восстановления…");continue;
      }
      throw;
     }
     if(generation!=enrollmentGeneration||cancelEnrollment)return;
     if(answer.status=="approved"){
      EnrollmentClient.SaveApproved(answer.config,root);
      TicketStore.Write(Path.Combine(root,"approval-ticket"),ticket.ticket);
      host.Text=answer.config.host;port.Text=answer.config.port.ToString();slot.Text=answer.config.slot.ToString();
      SaveSettings();enrolling=false;
      if(!cancelEnrollment)await StartBridgeAsync();return;
     }
     if(EnrollmentClient.ShouldRenewPending(answer.status)){
      // A new code is needed only after a confirmed expiry, never after a
      // transient 429/503 or network error; keep the same device SSH key.
      Status("Код "+ticket.code+" истёк. Получаем новую заявку автоматически…");
      ticket=null;
      break;
     }
     if(answer.status=="denied"||answer.status=="revoked"){
      throw new InvalidOperationException("Заявка завершена сервером: "+answer.status+". Новая заявка требует ручного запуска.");
     }
    } // End this ticket's polling; expired tickets start a new submission.
    if(ticket!=null)break;
   } // End automatic expiry-recovery loop.
   }catch(Exception ex){if(generation==enrollmentGeneration&&!cancelEnrollment){enrolling=false;Status("Регистрация недоступна: "+ex.Message);}}
   finally{if(generation==enrollmentGeneration){enrolling=false;if(cancelEnrollment)Status("Запрос отменён.");}}
  }
  async Task StartBridgeAsync(){
   if(running)return;
   // Do not require or contact Windows OpenSSH Server. Execution stays
   // in the user logon token of THIS process.
   if(!await EnsureOpenSshClientAsync())return;
   if(String.IsNullOrWhiteSpace(host.Text)||String.IsNullOrWhiteSpace(slot.Text)||!File.Exists(Known)){
    if(EnsureKey()){
     MessageBox.Show("Этот компьютер ещё не зарегистрирован в Hermes Gate.\n\nКлюч устройства создан локально. Нажми «Скопировать ключ» в разделе регистрации и передай только публичный ключ оператору. До подтверждения сервером удалённый доступ не открывается.","Регистрация Hermes Connector",MessageBoxButtons.OK,MessageBoxIcon.Information);
     if(!advanced.Visible)setup.PerformClick();
    }
    return;
   }
   if(!Valid(true))return;
   if(!File.Exists(Ssh)){Error("OpenSSH Client не найден. Нажми установку SSH Client в окне коннектора.");return;}
   if(!File.Exists(Known)){Error("Нет проверенного known_hosts. Его выдаёт оператор после регистрации устройства.");return;}
   if(!EnsureKey())return;
   SaveSettings();
   try{
    if(userAgent==null)userAgent=new UserSessionAgent(TicketStore.Read(Path.Combine(root,"approval-ticket")),message=>{
     try{if(IsHandleCreated&&!IsDisposed)BeginInvoke(new Action(()=>LogAction(message)));}catch(ObjectDisposedException){}
    });
   }catch(Exception ex){Status("Не удалось запустить агент текущего пользователя: "+ex.Message);return;}
   sessionStarted=DateTime.UtcNow;UpdateDeadline();running=true;retryAt=DateTime.UtcNow.AddSeconds(10);Launch();
  }
  void Launch(){
   if(!running||DateTime.UtcNow>=deadline)return;
   int serverPort=int.Parse(port.Text),remote=int.Parse(slot.Text);
   if(userAgent==null){StopBridge();Status("Агент текущего пользователя остановлен, канал закрыт.");return;}
   string args="-v -N -T -p "+serverPort+" -R 127.0.0.1:"+remote+":127.0.0.1:"+userAgent.Port+" -i \""+Key+"\" -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=\""+Known+"\" "+SshTransportOptions.Flags+" hermes-bridge@"+host.Text.Trim();
   try{
    if(tunnel!=null){try{tunnel.Dispose();}catch{}tunnel=null;}
    forwardConfirmed=false;lastTunnelFailure="";
    ProcessStartInfo p=new ProcessStartInfo(Ssh,args);p.UseShellExecute=false;p.CreateNoWindow=true;p.RedirectStandardError=true;
    Process process=new Process();process.StartInfo=p;
    process.ErrorDataReceived+=(sender,e)=>{
     if(e.Data==null)return;
     bool isReady=SshEvents.ForwardReady(e.Data);
     string failure=SshEvents.HumanFailure(e.Data);
     if(!isReady&&failure==null)return;
     try{if(IsHandleCreated&&!IsDisposed)BeginInvoke(new Action(()=>{
      if(!running||tunnel!=process)return;
      if(isReady){forwardConfirmed=true;reconnect.Connected();Status("Туннель открыт к агенту пользователя "+(userAgent==null?"неизвестно":userAgent.UserName)+". Авторизованное исполнение проверяется отдельно.");}
      if(failure!=null){lastTunnelFailure=failure;Status(failure);}
     }));}catch(ObjectDisposedException){}
    };
    process.Start();tunnel=process;process.BeginErrorReadLine();Status("Ожидаем подтверждение канала от сервера…");
   }catch(Exception ex){Status("Ошибка подключения: "+ex.Message);}
  }
  DateTime retryAt=DateTime.MinValue; readonly ReconnectPolicy reconnect=new ReconnectPolicy();
  async Task TickAsync(){
   if(!running)return;
   if(userAgent==null){StopBridge();Status("Агент пользователя не запущен — доступ закрыт.");return;}
   if(!leaseCheckBusy&&DateTime.UtcNow>=nextLeaseCheck){
    leaseCheckBusy=true;nextLeaseCheck=DateTime.UtcNow.AddSeconds(15);
    try{
     string f=Path.Combine(root,"approval-ticket");
     if(File.Exists(f)){
      EnrollmentResult a=await EnrollmentClient.PollAsync(EnrollmentEndpoint,TicketStore.Read(f));
      if(running&&a.status=="revoking"){
       // Keep the ticket for retry until Gate verifies the reverse session is gone.
       await DisconnectAsync();
       return;
      }
      if(running&&a.status!="approved"){
       StopBridge();revocationPending=false;ClearLocalApproval();
       Status("Gate прекратил разрешение ("+a.status+"). Канал закрыт; новый доступ требует МОСТ.");return;
      }
     }
    }catch(WebException){/* transient HTTPS failure: SSH keepalive independently detects the tunnel */}
    catch(Exception ex){Status("Проверка разрешения Gate: "+ex.Message);}
    finally{leaseCheckBusy=false;}
   }
   if(DateTime.UtcNow>=deadline){await DisconnectAsync();Status("Время сессии истекло; проверяем отзыв разрешения на Gate.");return;}
   if(tunnel!=null&&!tunnel.HasExited)return;
   if(tunnel!=null){forwardConfirmed=false;Status(lastTunnelFailure.Length>0?lastTunnelFailure+" Повторное подключение…":"SSH-канал прерван. Повторное подключение…");}
   if(DateTime.UtcNow<retryAt)return;
   retryAt=DateTime.UtcNow.Add(reconnect.FailedDelay());Launch();
  }
  async Task<bool> EnsureRevokedAsync(){
   if(running||enrolling||revocationPending||File.Exists(Path.Combine(root,"approval-ticket"))){
    await DisconnectAsync();
    if(revocationPending)return false;
   }
   // Legacy approvals cannot safely be treated as revoked without a ticket.
   if(!String.IsNullOrWhiteSpace(slot.Text)&&!File.Exists(Path.Combine(root,"approval-ticket"))){
    Status("Старое разрешение нельзя отозвать автоматически. Требуется операторский отзыв МОСТ.");
    return false;
   }
   return true;
  }
  async Task ExitWithRevokeAsync(){
   if(quitting||revoking)return;
   if(!await EnsureRevokedAsync()){
    if(MessageBox.Show("Локальный туннель остановлен, но Gate не подтвердил отзыв.\n\n"+
       "Можно закрыть программу локально, сохранив старую заявку и ключ для повторного отзыва. " +
       "Это НЕ означает прекращения серверных разрешений.\n\nЗакрыть локально?",
       "Ожидается отзыв МОСТ",MessageBoxButtons.YesNo,MessageBoxIcon.Warning,MessageBoxDefaultButton.Button2)!=DialogResult.Yes)return;
   }
   StopBridge();quitting=true;Close();
  }
  async Task DisconnectAsync(){
   // Stop the transport immediately, then revoke this session on Gate before allowing a new registration.
   if(revoking)return;revoking=true;
   StopBridge();
   string ticketFile=Path.Combine(root,"approval-ticket");
   revocationPending=File.Exists(ticketFile);
   if(!File.Exists(ticketFile)){
    Status("Туннель закрыт. У прежней регистрации нет сохранённого билета; серверное разрешение может оставаться активным. Обратись к оператору МОСТ для отзыва.");revoking=false;return;
   }
   try{
    string ticket=TicketStore.Read(ticketFile).Trim();
    if(!await EnrollmentClient.RevokeAsync(EnrollmentEndpoint,ticket))throw new InvalidOperationException("Gate не подтвердил отзыв");
    ClearLocalApproval();revocationPending=false;Status("Отключено. Gate отозвал разрешение; новое подключение потребует подтверждения.");
   }catch(Exception ex){Status("Туннель закрыт, но отзыв на Gate не подтверждён: "+ex.Message+". Повтори «Отключить» после восстановления связи.");}
   finally{revoking=false;Status(revocationPending?"Отключено локально. Отзыв разрешения на Gate не завершён — нажми «Отключить» ещё раз.":"Доступ закрыт.");}
  }
  void ClearLocalApproval(){
   foreach(string f in new[]{"approval-ticket","approved-bridge.cfg","known_hosts"}){try{string p=Path.Combine(root,f);if(File.Exists(p))File.Delete(p);}catch{}}
   host.Text="";slot.Text="";port.Text="22471";activeMostCode="";
  }
  void StopBridge(){
   cancelEnrollment=true;enrollmentGeneration++;enrolling=false;running=false;activeMostCode="";forwardConfirmed=false;lastTunnelFailure="";
   if(tunnel!=null){try{if(!tunnel.HasExited)tunnel.Kill();tunnel.Dispose();}catch{}tunnel=null;}
   if(userAgent!=null){try{userAgent.Dispose();}catch{}userAgent=null;}
   Status("Остановлено. Туннель и агент текущего пользователя завершены.");
  }
 }
}
