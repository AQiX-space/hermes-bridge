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
  [STAThread] static void Main(string[] args){if(args.Length>0 && args[0]=="--probe"){var a=new string[args.Length-1];Array.Copy(args,1,a,0,a.Length);Environment.ExitCode=TunnelProbe.Run(a);return;}Application.EnableVisualStyles();Application.SetCompatibleTextRenderingDefault(false);Application.Run(new BridgeForm());}
 }
 sealed class BridgeForm : Form {
  readonly string root=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"HermesBridge");
  TextBox host=new TextBox(),port=new TextBox(),slot=new TextBox(),known=new TextBox(),device=new TextBox();
  NumericUpDown ttl=new NumericUpDown(); CheckBox autoDisconnect=new CheckBox(); Label mostCode=new Label(); Label state=new Label(); Button start=new Button(),stop=new Button(),reload=new Button(),save=new Button(),import=new Button();
  NotifyIcon tray=new NotifyIcon(); ToolStripMenuItem trayToggle; Icon connectedTrayIcon; System.Windows.Forms.Timer heartbeat=new System.Windows.Forms.Timer();
  Process tunnel; DateTime deadline; bool running=false, quitting=false, updating=false, forwardConfirmed=false, enrolling=false, cancelEnrollment=false; int enrollmentGeneration=0; string lastTunnelFailure="";
  string Config {get{return Path.Combine(root,"client.ini");}}
  string Ssh {get{return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),"OpenSSH","ssh.exe");}}
  string Key {get{return Path.Combine(root,"keys","device_ed25519");}}
  string Known {get{return Path.Combine(root,"known_hosts");}}
  Panel advanced=new Panel(); Label subtitle=new Label(), deviceInfo=new Label(), connectionInfo=new Label(), expiryInfo=new Label(); Button setup=new Button(), keyCopy=new Button(), shortcut=new Button(); LinkLabel updates=new LinkLabel(); System.Windows.Forms.Timer updateTimer=new System.Windows.Forms.Timer();
  TextBox actionLog=new TextBox(); Label sshInfo=new Label(); Button uninstall=new Button(), closeApp=new Button(), copyLog=new Button(); LinkLabel installSsh=new LinkLabel(), sshCheck=new LinkLabel(); string sshVersion=null; bool updateAvailable=false; string activeMostCode=""; bool revoking=false; bool revocationPending=false; bool leaseCheckBusy=false; DateTime nextLeaseCheck=DateTime.MinValue;
  Color ink=Color.FromArgb(37,31,25), muted=Color.FromArgb(115,99,83), blue=Color.FromArgb(150,85,41), surface=Color.FromArgb(248,244,238);
  public BridgeForm(){
   Text="Hermes Connector 0.2.3"; Width=890;Height=566;MinimumSize=new Size(890,566);MaximumSize=new Size(890,566);StartPosition=FormStartPosition.CenterScreen;
   Font=new Font("Segoe UI",10f);BackColor=Color.White;ForeColor=ink;FormBorderStyle=FormBorderStyle.FixedSingle;MaximizeBox=false;
   Directory.CreateDirectory(root);Directory.CreateDirectory(Path.Combine(root,"keys"));
   Label heading=new Label(){Text="Hermes Connector",Font=new Font("Segoe UI Semibold",19,FontStyle.Bold),Left=30,Top=24,Width=388,Height=42};Controls.Add(heading);
   subtitle=new Label(){Text="Версия 0.2.3",ForeColor=muted,Left=31,Top=74,Width=255,Height=27};Controls.Add(subtitle);
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
   import.Click+=(s,e)=>ImportProvision();save.Click+=(s,e)=>SaveSettings();reload.Click+=(s,e)=>{StopBridge();LoadSettings();};
   start.Click+=async (s,e)=>await StartOrEnrollAsync();stop.Click+=async (s,e)=>await DisconnectAsync();
   setup.Visible=false;advanced.Visible=false;
   stop.BackColor=Color.FromArgb(176,56,56);stop.FlatAppearance.BorderSize=0;
   sshInfo.SetBounds(31,119,235,28);sshInfo.ForeColor=muted;Controls.Add(sshInfo);
   installSsh.Text="Установить";installSsh.SetBounds(335,122,96,25);installSsh.TextAlign=ContentAlignment.MiddleRight;installSsh.LinkColor=blue;Controls.Add(installSsh);
   sshCheck.Text="Проверить";sshCheck.SetBounds(335,122,96,25);sshCheck.TextAlign=ContentAlignment.MiddleRight;sshCheck.LinkColor=blue;Controls.Add(sshCheck);
   sshCheck.Click+=(s,e)=>{sshVersion=null;UpdateSshState();Status("OpenSSH проверен.");};
   installSsh.Click+=(s,e)=>InstallOpenSsh();
   shortcut.Parent= this;shortcut.SetBounds(28,376,190,37);shortcut.Visible=true;
   closeApp.Text="Закрыть Connector";closeApp.SetBounds(230,376,201,37);closeApp.Click+=async (s,e)=>await ExitWithRevokeAsync();Controls.Add(closeApp);
   Label logTitle=new Label(){Text="Журнал действий",Left=467,Top=33,Width=376,Height=28,Font=new Font("Segoe UI Semibold",13,FontStyle.Bold)};Controls.Add(logTitle);
   actionLog.SetBounds(463,78,395,401);actionLog.Multiline=true;actionLog.ScrollBars=ScrollBars.Vertical;actionLog.ReadOnly=true;actionLog.BorderStyle=BorderStyle.FixedSingle;actionLog.BackColor=Color.FromArgb(251,249,246);actionLog.ForeColor=ink;actionLog.Font=new Font("Consolas",9);Controls.Add(actionLog);
   copyLog.Text="Копировать журнал";copyLog.SetBounds(674,492,184,30);copyLog.Click+=(s,e)=>Clipboard.SetText(actionLog.Text);Controls.Add(copyLog);
   autoDisconnect.Text="Автоматическое отключение";autoDisconnect.SetBounds(30,429,238,28);autoDisconnect.Checked=false;Controls.Add(autoDisconnect);
   ttl.Parent=this;ttl.SetBounds(302,429,75,28);ttl.Minimum=5;ttl.Maximum=1440;ttl.Value=60;ttl.Enabled=false;
   autoDisconnect.CheckedChanged+=(sender,e)=>{ttl.Enabled=autoDisconnect.Checked;if(running)deadline=autoDisconnect.Checked?DateTime.UtcNow.AddMinutes((double)ttl.Value):DateTime.MaxValue;Status("Настройки таймера изменены.");};
   Controls.Add(new Label(){Text="мин",Left=384,Top=434,Width=45});
   uninstall.Text="Полностью удалить Connector";uninstall.SetBounds(28,496,403,30);uninstall.FlatStyle=FlatStyle.Flat;uninstall.ForeColor=Color.FromArgb(176,56,56);Controls.Add(uninstall);
   uninstall.Click+=async (s,e)=>await UninstallConnectorAsync();
   UpdateSshState();
   Icon=System.Drawing.Icon.ExtractAssociatedIcon(System.Reflection.Assembly.GetExecutingAssembly().Location);tray.Icon=Icon;tray.Text="Hermes Connector";tray.Visible=true;tray.DoubleClick+=(s,e)=>ShowMain();tray.BalloonTipTitle="Hermes Connector";tray.BalloonTipText="Работает в области уведомлений. Двойной щелчок открывает окно.";
   connectedTrayIcon=MakeConnectedTrayIcon(Icon);
   ContextMenuStrip menu=new ContextMenuStrip();menu.Items.Add("Открыть",null,(s,e)=>ShowMain());
   trayToggle=new ToolStripMenuItem("Подключить");trayToggle.Click+=async (s,e)=>{if(running||enrolling||revocationPending)await DisconnectAsync();else await StartOrEnrollAsync();};menu.Items.Add(trayToggle);
   menu.Items.Add("Выход",null,async (s,e)=>await ExitWithRevokeAsync());tray.ContextMenuStrip=menu;
   // Automatic updates only while remote support is disconnected. Signed manifest required.
   updateTimer.Interval=6*60*60*1000;
   updateTimer.Tick+=async (s,e)=>await CheckAndInstallUpdateAsync(true);
   updateTimer.Start();
   Shown+=async (s,e)=>await CheckAndInstallUpdateAsync(true);
   heartbeat.Interval=2000;heartbeat.Tick+=async (s,e)=>await TickAsync();heartbeat.Start();
   LoadSettings();EnsureDesktopShortcut();FormClosing+=(s,e)=>{if(!quitting){e.Cancel=true;Hide();}else{StopBridge();tray.Visible=false;tray.Dispose();if(connectedTrayIcon!=null)connectedTrayIcon.Dispose();}};
  }
  async System.Threading.Tasks.Task CheckAndInstallUpdateAsync(bool automatic){
   if(updating||quitting)return;
   if(running){if(!automatic)MessageBox.Show("Сначала отключи активный сеанс поддержки.","Обновление");return;}
   updating=true;updates.Enabled=false;updates.Text="Проверка…";
   try {
    GitHubUpdater.Release manifest=await GitHubUpdater.CheckAsync();
    updateAvailable=manifest!=null;
    if(manifest==null){if(!automatic)Status("Установлена актуальная версия Connector.");return;}
    if(automatic){Status("Доступна версия "+manifest.tagName+". Нажми «Обновить».");return;}
    if(running||quitting)return;
    if(!automatic && MessageBox.Show("Доступна версия "+manifest.tagName+". Установить?","Гермес Мост",MessageBoxButtons.YesNo)!=DialogResult.Yes)return;
    updates.Text="Загрузка и проверка обновления…";
    string staged=await GitHubUpdater.StageAsync(manifest,Path.Combine(root,"updates"));
    if(running||quitting)return;
    GitHubUpdater.Apply(manifest,staged);
    quitting=true;Close();
   }catch(Exception ex){
    if(!automatic)MessageBox.Show(""+ex.Message,"Гермес Мост",MessageBoxButtons.OK,MessageBoxIcon.Warning);
    else updates.Text="Автообновление недоступно";
   }finally{updating=false;updates.Enabled=true;if(!quitting)updates.Text=updateAvailable?"● Обновить":"Проверить";updates.LinkColor=updateAvailable?Color.FromArgb(36,133,78):blue;}
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
  void ShowMain(){Show();WindowState=FormWindowState.Normal;Activate();}
  void Status(string value){
   if(state==null)return;
   bool processAlive=false;
   try{processAlive=tunnel!=null&&!tunnel.HasExited;}catch{}
   state.Text=running&&processAlive&&forwardConfirmed?"Подключено":enrolling?"Ожидаем разрешение":running?"Подключение…":"Доступ отключён";
   state.ForeColor=running&&processAlive&&forwardConfirmed?Color.FromArgb(22,101,52):running?blue:ink;
   connectionInfo.Text=value;
   deviceInfo.Text="Компьютер: "+(device.Text.Trim().Length>0?device.Text.Trim():Environment.MachineName);mostCode.Text=activeMostCode;
   expiryInfo.Text=running&&autoDisconnect.Checked?"Отключение: "+deadline.ToLocalTime().ToString("HH:mm"):"Автоотключение выключено";
   bool connected=running&&processAlive&&forwardConfirmed;
   start.Visible=!running&&!enrolling&&!revoking&&!revocationPending;stop.Visible=running||enrolling||revoking||revocationPending;start.Enabled=!running&&!enrolling&&!revoking&&!revocationPending;stop.Enabled=(running||enrolling||revocationPending)&&!revoking;
   if(trayToggle!=null){trayToggle.Text=running||enrolling||revocationPending?"Отключить":"Подключить";trayToggle.Enabled=true;}
   if(tray.Visible){tray.Icon=connected&&connectedTrayIcon!=null?connectedTrayIcon:Icon;tray.Text=connected?"Hermes Connector — подключён":enrolling?"Hermes Connector — ожидание":"Hermes Connector — отключён";}
   UpdateSshState();LogAction(value);
  }
  void LogAction(string message){
   if(String.IsNullOrWhiteSpace(message)||actionLog.IsDisposed)return;
   if(actionLog.TextLength>24000)actionLog.Text=actionLog.Text.Substring(actionLog.TextLength-12000);
   actionLog.AppendText(DateTime.Now.ToString("HH:mm:ss")+"  "+message+Environment.NewLine);
  }
  void UpdateSshState(){
   string sshExe=Ssh;
   bool installed=File.Exists(sshExe);
   if(installed&&sshVersion==null){
    sshVersion="доступен";
    try{
     var p=new ProcessStartInfo(sshExe,"-V"){UseShellExecute=false,CreateNoWindow=true,RedirectStandardError=true};
     using(var proc=Process.Start(p)){
      string line=proc.StandardError.ReadLine();
      if(!proc.WaitForExit(2500)){proc.Kill();}else if(!String.IsNullOrWhiteSpace(line)){
       var match=System.Text.RegularExpressions.Regex.Match(line,@"OpenSSH[_ ](?:for_Windows_)?([0-9.]+p[0-9]+)");
       sshVersion=match.Success?match.Groups[1].Value:"доступен";
      }
     }
    }catch{}
   }
   sshInfo.Text=installed?"OpenSSH: "+sshVersion:"OpenSSH: —";
   installSsh.Visible=!installed;sshCheck.Visible=installed;
  }
  void InstallOpenSsh(){
   try{
    if(MessageBox.Show("Установить компонент Windows OpenSSH Client? Потребуются права администратора.","Hermes Connector",MessageBoxButtons.YesNo)!=DialogResult.Yes)return;
    var ps=new ProcessStartInfo("powershell.exe","-NoProfile -Command \"Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0\"");ps.UseShellExecute=true;ps.Verb="runas";Process.Start(ps);
    Status("Установка OpenSSH запущена. После завершения нажми «Подключить».");
   }catch(Exception ex){Status("Не удалось запустить установку OpenSSH: "+ex.Message);}
  }
  void LoadSettings(){
   device.Text=Environment.MachineName;host.Text="";port.Text="22471";slot.Text="";known.Text=Known;ttl.Value=60;
   if(File.Exists(Config)){foreach(string line in File.ReadAllLines(Config,Encoding.UTF8)){
    int i=line.IndexOf('=');if(i<1)continue;string name=line.Substring(0,i),value=line.Substring(i+1);
    if(name=="device")device.Text=value;if(name=="host")host.Text=value;if(name=="port")port.Text=value;if(name=="slot")slot.Text=value;
    int n;if(name=="ttl"&&int.TryParse(value,out n))ttl.Value=Math.Max(5,Math.Min(1440,n));
   }}
   Status("Нажми «Подключить Гермеса» для запроса доступа.");
  }
  void SaveSettings(){
   if(!Valid(false))return;
   string result="device="+device.Text.Trim()+"\nhost="+host.Text.Trim()+"\nport="+port.Text.Trim()+"\nslot="+slot.Text.Trim()+"\nttl="+ttl.Value+"\n";
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
  const string EnrollmentApi="https://de2.nod.aqixnet.com:18512/"; // DE2 trusted HTTPS enrollment.
  async Task StartOrEnrollAsync(){
   if(running||enrolling||revoking||revocationPending)return;
   if(!EnsureKey())return;
   if(!String.IsNullOrWhiteSpace(slot.Text)&&File.Exists(Known)&&File.Exists(Path.Combine(root,"approval-ticket"))){
    try{
     EnrollmentResult a=await EnrollmentClient.PollAsync(new Uri(EnrollmentApi),TicketStore.Read(Path.Combine(root,"approval-ticket")));
     if(a.status=="approved"&&EnrollmentClient.Valid(a.config)&&a.config.slot.ToString()==slot.Text.Trim()&&a.config.host==host.Text.Trim()){
      StartBridge();return;
     }
     Status("Прежнее разрешение на Gate больше не действует. Требуется новый запрос.");ClearLocalApproval();
    }catch(Exception ex){Status("Невозможно проверить ранее выданное разрешение: "+ex.Message);return;}
   }
   enrolling=true;cancelEnrollment=false;int generation=++enrollmentGeneration;Status("Отправляем заявку на доступ…");
   try{
    Uri endpoint=new Uri(EnrollmentApi);
    EnrollmentTicket ticket=null;
    while(ticket==null&&!cancelEnrollment&&generation==enrollmentGeneration){
     bool retry=false;
     try{ticket=await EnrollmentClient.SubmitAsync(endpoint,device.Text.Trim(),File.ReadAllText(Key+".pub").Trim());}
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
    activeMostCode=ticket.code;Status("Код МОСТ: "+ticket.code+" · Назови его при подтверждении.");
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
      if(!cancelEnrollment)StartBridge();return;
     }
     if(answer.status=="expired"||answer.status=="denied"||answer.status=="revoked"){
      throw new InvalidOperationException("Заявка завершена сервером: "+answer.status+". Для новой заявки нажми «Подключить».");
     }
    }
   }catch(Exception ex){if(generation==enrollmentGeneration&&!cancelEnrollment){enrolling=false;Status("Регистрация недоступна: "+ex.Message);}}
   finally{if(generation==enrollmentGeneration){enrolling=false;if(cancelEnrollment)Status("Запрос отменён.");}}
  }
  void StartBridge(){
   if(running)return;
   if(String.IsNullOrWhiteSpace(host.Text)||String.IsNullOrWhiteSpace(slot.Text)||!File.Exists(Known)){
    if(EnsureKey()){
     MessageBox.Show("Этот компьютер ещё не зарегистрирован в Hermes Gate.\n\nКлюч устройства создан локально. Нажми «Скопировать ключ» в разделе регистрации и передай только публичный ключ оператору. До подтверждения сервером удалённый доступ не открывается.","Регистрация Hermes Connector",MessageBoxButtons.OK,MessageBoxIcon.Information);
     if(!advanced.Visible)setup.PerformClick();
    }
    return;
   }
   if(!Valid(true))return;
   if(!File.Exists(Ssh)){Error("OpenSSH Client отсутствует. Установи компонент Windows OpenSSH Client.");return;}
   if(!File.Exists(Known)){Error("Нет проверенного known_hosts. Его выдаёт оператор после регистрации устройства.");return;}
   if(!EnsureKey())return;
   SaveSettings();
   deadline=autoDisconnect.Checked?DateTime.UtcNow.AddMinutes((double)ttl.Value):DateTime.MaxValue;running=true;retryAt=DateTime.UtcNow.AddSeconds(10);Launch();
  }
  void Launch(){
   if(!running||DateTime.UtcNow>=deadline)return;
   int serverPort=int.Parse(port.Text),remote=int.Parse(slot.Text);
   string args="-v -N -T -p "+serverPort+" -R 127.0.0.1:"+remote+":127.0.0.1:22 -i \""+Key+"\" -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=\""+Known+"\" -o ExitOnForwardFailure=yes -o ServerAliveInterval=30 -o ServerAliveCountMax=3 hermes-bridge@"+host.Text.Trim();
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
      if(isReady){forwardConfirmed=true;Status("Обратный порт подтверждён сервером.");}
      if(failure!=null){lastTunnelFailure=failure;Status(failure);}
     }));}catch(ObjectDisposedException){}
    };
    process.Start();tunnel=process;process.BeginErrorReadLine();Status("Ожидаем подтверждение канала от сервера…");
   }catch(Exception ex){Status("Ошибка подключения: "+ex.Message);}
  }
  DateTime retryAt=DateTime.MinValue;
  async Task TickAsync(){
   if(!running)return;
   if(!leaseCheckBusy&&DateTime.UtcNow>=nextLeaseCheck){
    leaseCheckBusy=true;nextLeaseCheck=DateTime.UtcNow.AddSeconds(15);
    try{
     string f=Path.Combine(root,"approval-ticket");
     if(File.Exists(f)){
      EnrollmentResult a=await EnrollmentClient.PollAsync(new Uri(EnrollmentApi),TicketStore.Read(f));
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
   retryAt=DateTime.UtcNow.AddSeconds(10);Launch();
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
    MessageBox.Show("Gate не подтвердил отзыв доступа. Приложение останется открытым для повторной попытки.","Отключение не завершено",MessageBoxButtons.OK,MessageBoxIcon.Warning);
    return;
   }
   quitting=true;Close();
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
    if(!await EnrollmentClient.RevokeAsync(new Uri(EnrollmentApi),ticket))throw new InvalidOperationException("Gate не подтвердил отзыв");
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
   Status("Остановлено. Локальный процесс туннеля завершён.");
  }
 }
}
