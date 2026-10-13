using System;
namespace HermesBridge {
 public static class SshEvents {
  public static bool ForwardReady(string message){return message!=null && message.IndexOf("remote forward success for:",StringComparison.OrdinalIgnoreCase)>=0;}
  public static string HumanFailure(string line){
   if(String.IsNullOrEmpty(line))return null;
   if(line.IndexOf("Permission denied",StringComparison.OrdinalIgnoreCase)>=0)return "Шлюз отклонил ключ устройства. Требуется регистрация.";
   if(line.IndexOf("Host key verification failed",StringComparison.OrdinalIgnoreCase)>=0)return "Ключ сервера не совпадает с доверенным. Соединение заблокировано.";
   if(line.IndexOf("remote port forwarding failed",StringComparison.OrdinalIgnoreCase)>=0)return "Шлюз не разрешил обратный порт для этого устройства.";
   if(line.IndexOf("Could not resolve hostname",StringComparison.OrdinalIgnoreCase)>=0)return "Адрес шлюза не найден в DNS.";
   if(line.IndexOf("Connection timed out",StringComparison.OrdinalIgnoreCase)>=0 || line.IndexOf("Connection refused",StringComparison.OrdinalIgnoreCase)>=0)return "Шлюз недоступен по сети.";
   if(line.IndexOf("UNPROTECTED PRIVATE KEY FILE",StringComparison.OrdinalIgnoreCase)>=0 || line.IndexOf("bad permissions",StringComparison.OrdinalIgnoreCase)>=0)return "Недопустимые права доступа к ключу устройства.";
   return null;
  }
 }
}
