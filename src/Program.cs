using System;
using System.IO;
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
  NumericUpDown ttl=new NumericUpDown(); Label state=new Label(); Button start=new Button(),stop=new Button(),reload=new Button(),save=new Button(),import=new Button();
  NotifyIcon tray=new NotifyIcon(); System.Windows.Forms.Timer heartbeat=new System.Windows.Forms.Timer();
  Process tunnel; DateTime deadline; bool running=false, quitting=false, updating=false, forwardConfirmed=false, enrolling=false, cancelEnrollment=false; int enrollmentGeneration=0; string lastTunnelFailure="";
  string Config {get{return Path.Combine(root,"client.ini");}}
  string Ssh {get{return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),"OpenSSH","ssh.exe");}}
  string Key {get{return Path.Combine(root,"keys","device_ed25519");}}
  string Known {get{return Path.Combine(root,"known_hosts");}}
  Panel advanced=new Panel(); Label subtitle=new Label(), deviceInfo=new Label(), connectionInfo=new Label(), expiryInfo=new Label(); Button setup=new Button(), keyCopy=new Button(), updates=new Button(), shortcut=new Button(); System.Windows.Forms.Timer updateTimer=new System.Windows.Forms.Timer();
  Color ink=Color.FromArgb(37,31,25), muted=Color.FromArgb(115,99,83), blue=Color.FromArgb(150,85,41), surface=Color.FromArgb(248,244,238);
  public BridgeForm(){
   Text="Hermes Connector 0.2.0-beta.10"; Width=520;Height=535;MinimumSize=new Size(520,535);MaximumSize=new Size(520,865);StartPosition=FormStartPosition.CenterScreen;
   Font=new Font("Segoe UI",10f);BackColor=Color.White;ForeColor=ink;FormBorderStyle=FormBorderStyle.FixedSingle;MaximizeBox=false;
   Directory.CreateDirectory(root);Directory.CreateDirectory(Path.Combine(root,"keys"));
   Label heading=new Label(){Text="Hermes Connector",Font=new Font("Segoe UI Semibold",20,FontStyle.Bold),Left=25,Top=21,Width=430,Height=42};Controls.Add(heading);
   subtitle=new Label(){Text="Версия 0.2.0-beta.10 · Доступ только с разрешения",ForeColor=muted,Left=28,Top=66,Width=435,Height=27};Controls.Add(subtitle);
   Panel card=new Panel(){Left=22,Top=110,Width=455,Height=140,BackColor=surface};Controls.Add(card);
   state.Left=17;state.Top=16;state.Width=417;state.Height=42;state.Font=new Font("Segoe UI Semibold",17,FontStyle.Bold);card.Controls.Add(state);
   connectionInfo.Left=18;connectionInfo.Top=66;connectionInfo.Width=417;connectionInfo.Height=30;connectionInfo.ForeColor=muted;card.Controls.Add(connectionInfo);
   deviceInfo.Left=18;deviceInfo.Top=101;deviceInfo.Width=420;deviceInfo.Height=28;deviceInfo.ForeColor=muted;card.Controls.Add(deviceInfo);
   start.Text="Подключить Гермеса";start.Left=22;start.Top=266;start.Width=455;start.Height=49;start.FlatStyle=FlatStyle.Flat;start.FlatAppearance.BorderSize=0;start.BackColor=blue;start.ForeColor=Color.White;start.Font=new Font("Segoe UI Semibold",12,FontStyle.Bold);Controls.Add(start);
   stop.Text="Отключить доступ";stop.Left=22;stop.Top=327;stop.Width=455;stop.Height=43;stop.FlatStyle=FlatStyle.Flat;stop.BackColor=Color.White;stop.ForeColor=ink;Controls.Add(stop);
   setup.Text="Настройки и регистрация  ▾";setup.Left=22;setup.Top=384;setup.Width=455;setup.Height=40;setup.FlatStyle=FlatStyle.Flat;setup.ForeColor=muted;Controls.Add(setup);
   updates.Text="Проверить обновления ↗";updates.Left=22;updates.Top=430;updates.Width=455;updates.Height=34;updates.FlatStyle=FlatStyle.Flat;updates.ForeColor=blue;Controls.Add(updates);
   updates.Click+=async (s,e)=>await CheckAndInstallUpdateAsync(false);
   expiryInfo.Left=25;expiryInfo.Top=469;expiryInfo.Width=440;expiryInfo.Height=28;expiryInfo.ForeColor=muted;Controls.Add(expiryInfo);
   advanced.Left=0;advanced.Top=505;advanced.Width=495;advanced.Height=280;advanced.Visible=false;Controls.Add(advanced);
   int y=5;AddLine("Устройство",device,ref y);AddLine("Сервер",host,ref y);AddLine("Порт сервера",port,ref y);AddLine("Порт сессии",slot,ref y);
   ttl.Minimum=5;ttl.Maximum=240;ttl.Value=60;ttl.Left=270;ttl.Top=y;ttl.Width=90;
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
   start.Click+=async (s,e)=>await StartOrEnrollAsync();stop.Click+=(s,e)=>StopBridge();
   setup.Click+=(s,e)=>{advanced.Visible=!advanced.Visible;setup.Text=advanced.Visible?"Скрыть настройки  ▴":"Настройки и регистрация  ▾";Height=advanced.Visible?865:535;};
   Icon=System.Drawing.Icon.ExtractAssociatedIcon(System.Reflection.Assembly.GetExecutingAssembly().Location);tray.Icon=Icon;tray.Text="Hermes Connector";tray.Visible=true;tray.DoubleClick+=(s,e)=>ShowMain();tray.BalloonTipTitle="Hermes Connector";tray.BalloonTipText="Работает в области уведомлений. Двойной щелчок открывает окно.";
   ContextMenuStrip menu=new ContextMenuStrip();menu.Items.Add("Открыть",null,(s,e)=>ShowMain());menu.Items.Add("Подключить",null,async (s,e)=>await StartOrEnrollAsync());menu.Items.Add("Отключить",null,(s,e)=>StopBridge());menu.Items.Add("Выход",null,(s,e)=>{quitting=true;Close();});tray.ContextMenuStrip=menu;
   // Automatic updates only while remote support is disconnected. Signed manifest required.
   updateTimer.Interval=6*60*60*1000;
   updateTimer.Tick+=async (s,e)=>await CheckAndInstallUpdateAsync(true);
   updateTimer.Start();
   Shown+=async (s,e)=>await CheckAndInstallUpdateAsync(true);
   heartbeat.Interval=2000;heartbeat.Tick+=(s,e)=>Tick();heartbeat.Start();
   LoadSettings();EnsureDesktopShortcut();FormClosing+=(s,e)=>{if(!quitting){e.Cancel=true;Hide();}else{StopBridge();tray.Visible=false;tray.Dispose();}};
  }
  async System.Threading.Tasks.Task CheckAndInstallUpdateAsync(bool automatic){
   if(updating||quitting)return;
   if(running){if(!automatic)MessageBox.Show("Сначала отключи активный сеанс поддержки.","Обновление");return;}
   updating=true;updates.Enabled=false;updates.Text="Проверка подписанного обновления…";
   try {
    GitHubUpdater.Release manifest=await GitHubUpdater.CheckAsync();
    if(manifest==null){if(!automatic)MessageBox.Show("Новых подписанных обновлений нет.","Гермес Мост");return;}
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
   }finally{updating=false;updates.Enabled=true;if(!quitting)updates.Text="Проверить обновления";}
  }
  void AddLine(string title,TextBox t,ref int y){advanced.Controls.Add(new Label(){Text=title,Left=26,Top=y+4,Width=240});t.Left=270;t.Top=y;t.Width=189;advanced.Controls.Add(t);y+=34;}
  void EnsureDesktopShortcut(){
   try {
    string desktop=Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
    if(!String.IsNullOrWhiteSpace(desktop) && !File.Exists(Path.Combine(desktop,"Hermes Connector.lnk")))CreateDesktopShortcut(true);
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
  void ShowMain(){Show();WindowState=FormWindowState.Normal;Activate();}
  void Status(string value){
   if(state==null)return;
   bool processAlive=false;
   try{processAlive=tunnel!=null&&!tunnel.HasExited;}catch{}
   state.Text=running&&processAlive&&forwardConfirmed?"Канал открыт":enrolling?"Ожидаем разрешение":running?"Подключение…":"Доступ отключён";
   state.ForeColor=running&&processAlive&&forwardConfirmed?Color.FromArgb(22,101,52):running?blue:ink;
   connectionInfo.Text=value;
   deviceInfo.Text="Компьютер: "+(device.Text.Trim().Length>0?device.Text.Trim():Environment.MachineName);
   expiryInfo.Text=running?"Автоматическое отключение: "+deadline.ToLocalTime().ToString("HH:mm"):"Закрытие окна оставит программу в трее";
   start.Enabled=!running&&!enrolling;stop.Enabled=running||enrolling;
  }
  void LoadSettings(){
   device.Text=Environment.MachineName;host.Text="";port.Text="22471";slot.Text="";known.Text=Known;ttl.Value=60;
   if(File.Exists(Config)){foreach(string line in File.ReadAllLines(Config,Encoding.UTF8)){
    int i=line.IndexOf('=');if(i<1)continue;string name=line.Substring(0,i),value=line.Substring(i+1);
    if(name=="device")device.Text=value;if(name=="host")host.Text=value;if(name=="port")port.Text=value;if(name=="slot")slot.Text=value;
    int n;if(name=="ttl"&&int.TryParse(value,out n))ttl.Value=Math.Max(5,Math.Min(240,n));
   }}
   Status("Для подключения потребуется одобрение и регистрация устройства.");
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
   if(running||enrolling)return;
   if(!EnsureKey())return;
   if(!String.IsNullOrWhiteSpace(slot.Text)&&File.Exists(Known)){StartBridge();return;}
   enrolling=true;cancelEnrollment=false;int generation=++enrollmentGeneration;Status("Отправляем заявку на доступ…");
   try{
    Uri endpoint=new Uri(EnrollmentApi);
    EnrollmentTicket ticket=await EnrollmentClient.SubmitAsync(endpoint,device.Text.Trim(),File.ReadAllText(Key+".pub").Trim());
    if(generation!=enrollmentGeneration||cancelEnrollment)return;
    Status("Запрос отправлен. Ожидается разрешение оператора.");
    // Server expires pending tickets after 15 minutes; match that window.
    for(int i=0;i<300&&!cancelEnrollment;i++){
     await Task.Delay(3000);
     if(cancelEnrollment)break;
     EnrollmentResult answer=await EnrollmentClient.PollAsync(endpoint,ticket.ticket);
     if(generation!=enrollmentGeneration||cancelEnrollment)return;
     if(answer.status=="approved"){
      EnrollmentClient.SaveApproved(answer.config,root);
      host.Text=answer.config.host;port.Text=answer.config.port.ToString();slot.Text=answer.config.slot.ToString();
      SaveSettings();enrolling=false;
      if(!cancelEnrollment)StartBridge();return;
     }
     if(answer.status=="expired"||answer.status=="denied")throw new InvalidOperationException("Регистрация отклонена или истекла.");
    }
    if(!cancelEnrollment)throw new TimeoutException("Истекло ожидание подтверждения оператора.");
   }catch(Exception ex){if(generation==enrollmentGeneration&&!cancelEnrollment)Status("Регистрация недоступна: "+ex.Message);}
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
   deadline=DateTime.UtcNow.AddMinutes((double)ttl.Value);running=true;retryAt=DateTime.UtcNow.AddSeconds(10);Launch();
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
  void Tick(){
   if(!running)return;
   if(DateTime.UtcNow>=deadline){StopBridge();Status("Время сессии истекло; доступ закрыт.");return;}
   if(tunnel!=null&&!tunnel.HasExited)return;
   if(tunnel!=null){forwardConfirmed=false;if(lastTunnelFailure.Length>0)Status(lastTunnelFailure+" Повторное подключение…");}
   if(DateTime.UtcNow<retryAt)return;
   retryAt=DateTime.UtcNow.AddSeconds(10);Launch();
  }
  void StopBridge(){
   cancelEnrollment=true;enrollmentGeneration++;enrolling=false;running=false;forwardConfirmed=false;lastTunnelFailure="";
   if(tunnel!=null){try{if(!tunnel.HasExited)tunnel.Kill();tunnel.Dispose();}catch{}tunnel=null;}
   Status("Остановлено. Локальный процесс туннеля завершён.");
  }
 }
}
