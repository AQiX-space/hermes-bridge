using System;
using System.IO;
using System.Diagnostics;
using System.Reflection;
using System.Security.Cryptography;
using System.Windows.Forms;

// Emergency per-user installer for a 0.2.7/0.2.8 Connector deadlocked on DE2.
// Never changes enrollment state, tokens, SSH identity, firewall or server permissions.
class HermesRecoveryInstaller {
 const string ExpectedHash="737e274a6ab5797c0ea8277c5b632503bbc840128906119b61675db327615b42";
 static string Hash(byte[] b){using(var s=SHA256.Create())return BitConverter.ToString(s.ComputeHash(b)).Replace("-","").ToLowerInvariant();}
 static byte[] Embedded(){
  using(Stream stream=Assembly.GetExecutingAssembly().GetManifestResourceStream("HermesBridge.exe")){
   if(stream==null)throw new InvalidOperationException("В установщике отсутствует HermesBridge.exe");
   using(var mem=new MemoryStream()){stream.CopyTo(mem);byte[] bytes=mem.ToArray();if(Hash(bytes)!=ExpectedHash)throw new InvalidDataException("Контрольная сумма установщика не совпала");return bytes;}
  }
 }
 [STAThread]static int Main(string[] args){
  try{
   byte[] payload=Embedded();
   if(args.Length==1&&args[0]=="--verify-only"){Console.WriteLine("PASS SHA256 "+Hash(payload));return 0;}
   if(args.Length!=0)throw new InvalidOperationException("Неизвестный аргумент");
   Application.EnableVisualStyles();
   string msg="Hermes Connector 0.2.9 — аварийное восстановление.\n\n"+
    "Старый DE2 может не подтвердить отзыв, поэтому обычное обновление 0.2.7/0.2.8 блокируется.\n\n"+
    "Этот установщик обновит ТОЛЬКО программу в вашем Windows-профиле и откроет 0.2.9. " +
    "Ключи, билеты и сведения об отзывах не удаляются. Для перехода на GR2 потребуется отдельное подтверждение.\n\nПродолжить?";
   if(MessageBox.Show(msg,"Восстановление Гермес Коннектора",MessageBoxButtons.YesNo,MessageBoxIcon.Question,MessageBoxDefaultButton.Button2)!=DialogResult.Yes)return 1;
   string profile=Path.GetFullPath(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile)).TrimEnd(Path.DirectorySeparatorChar)+Path.DirectorySeparatorChar;
   int thisSession=Process.GetCurrentProcess().SessionId;
   foreach(string name in new[]{"HermesBridge","HermesConnector"}){
    foreach(Process proc in Process.GetProcessesByName(name)){
     try{
      if(proc.Id==Process.GetCurrentProcess().Id||proc.HasExited||proc.SessionId!=thisSession)continue;
      string path=Path.GetFullPath(proc.MainModule.FileName);
      if(!path.StartsWith(profile,StringComparison.OrdinalIgnoreCase))continue; // never touch another user's program
      if(MessageBox.Show("В вашем сеансе открыт Hermes Connector. Завершить только этот процесс для обновления?\n\n"+path,
        "Завершение старой версии",MessageBoxButtons.YesNo,MessageBoxIcon.Warning,MessageBoxDefaultButton.Button2)!=DialogResult.Yes)return 2;
      proc.Kill();
      if(!proc.WaitForExit(12000))throw new IOException("Старый Connector не завершился");
     }catch(System.ComponentModel.Win32Exception){throw new IOException("Нельзя безопасно закрыть работающий Connector. Закройте его через Диспетчер задач.");}
     finally{proc.Dispose();}
    }
   }
   string home=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"HermesBridge");
   Directory.CreateDirectory(home);
   string destination=Path.Combine(home,"HermesConnector.exe"), staged=destination+".new";
   string backup=null;
   try{
    if(File.Exists(staged))File.Delete(staged);
    File.WriteAllBytes(staged,payload);
    using(var file=File.OpenRead(staged))using(var sha=SHA256.Create()){
     string hash=BitConverter.ToString(sha.ComputeHash(file)).Replace("-","").ToLowerInvariant();
     if(hash!=ExpectedHash)throw new InvalidDataException("Ошибка проверки записанного файла");
    }
    if(File.Exists(destination)){
     backup=destination+".previous-"+DateTime.UtcNow.ToString("yyyyMMddHHmmss");
     File.Move(destination,backup);
    }
    try{File.Move(staged,destination);}catch{
     if(backup!=null&&File.Exists(backup)&&!File.Exists(destination))File.Move(backup,destination);
     throw;
    }
    try{Process.Start(new ProcessStartInfo(destination){UseShellExecute=true});}
    catch{
     File.Delete(destination);
     if(backup!=null&&File.Exists(backup))File.Move(backup,destination);
     throw;
    }
   }finally{if(File.Exists(staged))File.Delete(staged);}
   // New client corrects the desktop shortcut when started from LocalAppData.
   MessageBox.Show("Установлена 0.2.9.\n\nЕсли старый DE2 не отвечает, нажмите в новом окне «Аварийно на GR2». " +
    "Приложение сохранит старый ключ и заявку, затем запросит новый доступ.\n\nСтарое разрешение DE2 НЕ считается отозванным.",
    "Гермес Коннектор",MessageBoxButtons.OK,MessageBoxIcon.Information);
   return 0;
  }catch(Exception ex){MessageBox.Show(ex.Message,"Ошибка безопасной установки",MessageBoxButtons.OK,MessageBoxIcon.Error);return 9;}
 }
}
