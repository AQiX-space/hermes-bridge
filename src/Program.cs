using System;
using System.IO;
using System.Text;
using System.Linq;
using System.Diagnostics;
using System.Drawing;
using System.Windows.Forms;
using System.Security.Cryptography;
using System.Security.Principal;

namespace HermesBridge {
 static class App {
  [STAThread] static void Main(){Application.EnableVisualStyles();Application.SetCompatibleTextRenderingDefault(false);Application.Run(new BridgeForm());}
 }
 sealed class BridgeForm : Form {
  readonly string root=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"HermesBridge");
  TextBox host=new TextBox(),port=new TextBox(),slot=new TextBox(),known=new TextBox(),device=new TextBox();
  NumericUpDown ttl=new NumericUpDown(); Label state=new Label(); Button start=new Button(),stop=new Button(),reload=new Button(),save=new Button();
  NotifyIcon tray=new NotifyIcon(); System.Windows.Forms.Timer heartbeat=new System.Windows.Forms.Timer();
  Process tunnel; DateTime deadline; bool running=false, quitting=false;
  string Config {get{return Path.Combine(root,"client.ini");}}
  string Ssh {get{return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),"OpenSSH","ssh.exe");}}
  string Key {get{return Path.Combine(root,"keys","device_ed25519");}}
  string Known {get{return Path.Combine(root,"known_hosts");}}
  public BridgeForm(){
   Text="Гермес Мост · Windows"; Width=590;Height=480;StartPosition=FormStartPosition.CenterScreen;FormBorderStyle=FormBorderStyle.FixedDialog;MaximizeBox=false;
   Directory.CreateDirectory(root);Directory.CreateDirectory(Path.Combine(root,"keys"));
   int y=15;AddLine("Устройство",device,ref y);AddLine("Домен шлюза",host,ref y);AddLine("SSH-порт шлюза",port,ref y);AddLine("Обратный порт (выдаёт сервер)",slot,ref y);AddLine("Отпечаток host key / known_hosts",known,ref y);
   Label time=new Label(){Text="Сессия, минут",Left=16,Top=y+5,Width=240};Controls.Add(time);ttl.Left=264;ttl.Top=y;ttl.Width=85;ttl.Minimum=5;ttl.Maximum=240;ttl.Value=60;y+=38;
   save.Text="Save";start.Text="Start";stop.Text="Stop";reload.Text="Reload";
   Button[] buttons={save,start,stop,reload};for(int i=0;i<buttons.Length;i++){buttons[i].Left=18+i*135;buttons[i].Top=y;buttons[i].Width=120;Controls.Add(buttons[i]);}
   y+=45;Button enroll=new Button(){Text="Создать ключ / скопировать PUBLIC",Left=18,Top=y,Width=340};Controls.Add(enroll);enroll.Click+=(s,e)=>{if(EnsureKey()){Clipboard.SetText(File.ReadAllText(Key+".pub"));Status("Публичный ключ создан и скопирован. Передай его оператору для регистрации.");}};y+=38;state.Left=18;state.Top=y;state.Width=545;state.Height=55;Controls.Add(state);
   save.Click+=(s,e)=>SaveSettings();start.Click+=(s,e)=>StartBridge();stop.Click+=(s,e)=>StopBridge();reload.Click+=(s,e)=>{StopBridge();LoadSettings();};
   tray.Icon=SystemIcons.Shield;tray.Text="Гермес Мост";tray.Visible=true;tray.DoubleClick+=(s,e)=>ShowMain();
   ContextMenuStrip menu=new ContextMenuStrip();menu.Items.Add("Открыть",null,(s,e)=>ShowMain());menu.Items.Add("Start",null,(s,e)=>StartBridge());menu.Items.Add("Stop",null,(s,e)=>StopBridge());menu.Items.Add("Reload",null,(s,e)=>{StopBridge();LoadSettings();});menu.Items.Add("Exit",null,(s,e)=>{quitting=true;Close();});tray.ContextMenuStrip=menu;
   heartbeat.Interval=2000;heartbeat.Tick+=(s,e)=>Tick();heartbeat.Start();
   LoadSettings();FormClosing+=(s,e)=>{if(!quitting){e.Cancel=true;Hide();}else{StopBridge();tray.Visible=false;tray.Dispose();}};
  }
  void AddLine(string title,TextBox t,ref int y){Controls.Add(new Label(){Text=title,Left=16,Top=y+5,Width=243});t.Left=264;t.Top=y;t.Width=285;Controls.Add(t);y+=37;}
  void ShowMain(){Show();WindowState=FormWindowState.Normal;Activate();}
  void Status(string value){state.Text=value;state.ForeColor=running?Color.DarkGreen:Color.DarkSlateGray;}
  void LoadSettings(){
   device.Text=Environment.MachineName;host.Text="";port.Text="22471";slot.Text="";known.Text=Known;ttl.Value=60;
   if(File.Exists(Config)){foreach(string line in File.ReadAllLines(Config,Encoding.UTF8)){
    int i=line.IndexOf('=');if(i<1)continue;string name=line.Substring(0,i),value=line.Substring(i+1);
    if(name=="device")device.Text=value;if(name=="host")host.Text=value;if(name=="port")port.Text=value;if(name=="slot")slot.Text=value;
    int n;if(name=="ttl"&&int.TryParse(value,out n))ttl.Value=Math.Max(5,Math.Min(240,n));
   }}
   Status("Остановлено. Требуется регистрация публичного ключа и назначение порта оператором.");
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
  void Error(string message){MessageBox.Show(message,"Гермес Мост",MessageBoxButtons.OK,MessageBoxIcon.Warning);}
  bool EnsureKey(){
   if(File.Exists(Key))return true;
   string keygen=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),"OpenSSH","ssh-keygen.exe");
   if(!File.Exists(keygen)){Error("Требуется OpenSSH Client в Windows.");return false;}
   var psi=new ProcessStartInfo(keygen,"-q -t ed25519 -N \"\" -f \""+Key+"\"");psi.UseShellExecute=false;psi.CreateNoWindow=true;
   using(Process p=Process.Start(psi)){p.WaitForExit(15000);if(!p.HasExited){p.Kill();Error("Генерация ключа превысила 15 секунд");return false;}if(p.ExitCode!=0){Error("Не удалось создать ключ устройства");return false;}}
   return File.Exists(Key)&&File.Exists(Key+".pub");
  }
  void StartBridge(){
   if(running)return;if(!Valid(true))return;
   if(!File.Exists(Ssh)){Error("OpenSSH Client отсутствует. Установи компонент Windows OpenSSH Client.");return;}
   if(!File.Exists(Known)){Error("Нет проверенного known_hosts. Его выдаёт оператор после регистрации устройства.");return;}
   if(!EnsureKey())return;
   SaveSettings();
   deadline=DateTime.UtcNow.AddMinutes((double)ttl.Value);running=true;Launch();
  }
  void Launch(){
   if(!running||DateTime.UtcNow>=deadline)return;
   int serverPort=int.Parse(port.Text),remote=int.Parse(slot.Text);
   string args="-N -T -p "+serverPort+" -R 127.0.0.1:"+remote+":127.0.0.1:22 -i \""+Key+"\" -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=\""+Known+"\" -o ExitOnForwardFailure=yes -o ServerAliveInterval=30 -o ServerAliveCountMax=3 hermes-bridge@"+host.Text.Trim();
   try{
    ProcessStartInfo p=new ProcessStartInfo(Ssh,args);p.UseShellExecute=false;p.CreateNoWindow=true;
    tunnel=Process.Start(p);Status("Сессия активна до "+deadline.ToLocalTime().ToString("HH:mm")+". PID "+tunnel.Id);
   }catch(Exception ex){Status("Ошибка подключения: "+ex.Message);}
  }
  DateTime retryAt=DateTime.MinValue;
  void Tick(){
   if(!running)return;
   if(DateTime.UtcNow>=deadline){StopBridge();Status("Время сессии истекло; доступ закрыт.");return;}
   if(tunnel!=null&&!tunnel.HasExited)return;
   if(DateTime.UtcNow<retryAt)return;
   retryAt=DateTime.UtcNow.AddSeconds(10);Status("Нет связи. Повтор через 10 секунд.");Launch();
  }
  void StopBridge(){
   running=false;
   if(tunnel!=null){try{if(!tunnel.HasExited)tunnel.Kill();tunnel.Dispose();}catch{}tunnel=null;}
   Status("Остановлено. Локальный процесс туннеля завершён.");
  }
 }
}
