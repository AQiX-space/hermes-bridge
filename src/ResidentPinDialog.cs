using System;
using System.Drawing;
using System.Windows.Forms;

namespace HermesBridge {
 // Modal and owner-visible: no hidden PIN capture, keyboard hook or bypass.
 internal static class ResidentPinDialog {
  static string Prompt(IWin32Window owner,string title,string hint,bool password=true){
   using(var window=new Form()){
    window.Text=title;window.Font=new Font("Segoe UI",10f);window.Width=420;window.Height=185;
    window.MinimizeBox=false;window.MaximizeBox=false;window.ShowInTaskbar=false;
    window.FormBorderStyle=FormBorderStyle.FixedDialog;
    window.StartPosition=FormStartPosition.CenterParent;
    var label=new Label{Text=hint,Left=18,Top=15,Width=375,Height=48};window.Controls.Add(label);
    var input=new TextBox{Left=18,Top=72,Width=368,UseSystemPasswordChar=password,MaxLength=12};window.Controls.Add(input);
    var ok=new Button{Text="Подтвердить",Left=197,Top=112,Width=90,DialogResult=DialogResult.OK};window.Controls.Add(ok);
    var cancel=new Button{Text="Отмена",Left=296,Top=112,Width=90,DialogResult=DialogResult.Cancel};window.Controls.Add(cancel);
    window.AcceptButton=ok;window.CancelButton=cancel;
    window.Shown+=(s,e)=>input.Focus();
    if(window.ShowDialog(owner)!=DialogResult.OK)return null;
    return input.Text;
   }
  }
  public static bool Authenticate(IWin32Window owner,ResidentPinStore store){
   try{
    for(int i=0;i<5;i++){
     string entered=Prompt(owner,"PIN постоянного агента","Введите PIN для доступа к настройкам постоянного агента.");
     if(entered==null)return false;
     int seconds;
     if(store.Verify(entered,out seconds))return true;
     if(seconds>0){MessageBox.Show(owner,"Слишком много попыток. Повтори через "+seconds+" секунд.","Временная блокировка PIN",MessageBoxButtons.OK,MessageBoxIcon.Warning);return false;}
     MessageBox.Show(owner,"Неверный PIN.","Доступ к настройкам",MessageBoxButtons.OK,MessageBoxIcon.Warning);
    }
   }catch(Exception ex){
    MessageBox.Show(owner,"PIN-хранилище недоступно: "+ex.Message+". Настройки остаются закрытыми; отключить удалённую поддержку можно через трей.","PIN",MessageBoxButtons.OK,MessageBoxIcon.Error);
   }
   return false;
  }
  public static bool Change(IWin32Window owner,ResidentPinStore store){
   try{
    string old=Prompt(owner,"Изменение PIN","Введите действующий PIN текущего пользователя Windows.");
    if(old==null)return false;
    string next=Prompt(owner,"Новый PIN","Введите новый PIN: от 4 до 12 цифр. Не используйте 1111.");
    if(next==null)return false;
    string again=Prompt(owner,"Подтверждение PIN","Повторите новый PIN.");
    if(again==null)return false;
    if(next!=again){MessageBox.Show(owner,"Новый PIN не совпадает с повтором.","PIN");return false;}
    if(next=="1111"){MessageBox.Show(owner,"Начальный PIN 1111 небезопасен. Задайте другой.","PIN",MessageBoxButtons.OK,MessageBoxIcon.Warning);return false;}
    store.Change(old,next);
    MessageBox.Show(owner,"PIN изменён для текущего пользователя Windows.","PIN",MessageBoxButtons.OK,MessageBoxIcon.Information);
    return true;
   }catch(Exception ex){MessageBox.Show(owner,"PIN не изменён: "+ex.Message,"PIN",MessageBoxButtons.OK,MessageBoxIcon.Warning);return false;}
  }
 }
}
