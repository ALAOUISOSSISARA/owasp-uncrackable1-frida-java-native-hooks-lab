// ============================================================
// bypass_java.js — Lab14 Root Bypass
// Auteur: test sur owasp.mstg.uncrackable1
// Emulateur: Android API 30 x86_64
// Outil: Frida 16.1.3
// ============================================================

const cheminsSuspects = [
  "/system/bin/su", "/system/xbin/su", "/sbin/su", "/system/su",
  "/system/app/Superuser.apk", "/system/app/SuperSU.apk",
  "/system/bin/busybox", "/system/xbin/busybox"
];

function enMinuscules(s){
  try { return (""+s).toLowerCase(); } catch(_) { return ""; }
}

Java.perform(function () {

  // --- Neutraliser Build.TAGS ---
  try {
    const InfoBuild = Java.use('android.os.Build');
    Object.defineProperty(InfoBuild, 'TAGS', {
      get: function() { return 'release-keys'; }
    });
    console.log('[+] Build.TAGS force en release-keys');
  } catch (e) { console.log('[-] Echec hook Build.TAGS:', e); }

  // --- Bloquer RootBeer si present ---
  try {
    const DetecteurRoot = Java.use('com.scottyab.rootbeer.RootBeer');
    DetecteurRoot.isRooted.implementation = function(){
      console.log('[+] RootBeer.isRooted bloque -> false');
      return false;
    };
  } catch(e) { console.log('[*] RootBeer absent sur cette app'); }

  // --- Bloquer File.exists sur chemins suspects ---
  try {
    const FichierJava = Java.use('java.io.File');
    FichierJava.exists.implementation = function () {
      const chemin = this.getAbsolutePath();
      if (cheminsSuspects.indexOf(chemin) !== -1) {
        console.log('[+] File.exists bloque pour:', chemin);
        return false;
      }
      return this.exists.call(this);
    };
  } catch (e) { console.log('[-] Echec hook File.exists:', e); }

  // --- Bloquer Runtime.exec sur commandes suspectes ---
  try {
    const Exec = Java.use('java.lang.Runtime');
    const ChaineJava = Java.use('java.lang.String');
    const TableauChaines = Java.use('[Ljava.lang.String;');

    function commandeSuspecte(cmd){
      const s = enMinuscules(Array.isArray(cmd) ? cmd.join(' ') : cmd);
      return s.startsWith('su') || s.includes(' which su') || s.includes(' busybox') || s.includes(' su ');
    }

    Exec.exec.overload('java.lang.String').implementation = function (cmd) {
      if (commandeSuspecte(cmd)) {
        console.log('[+] Runtime.exec bloque:', cmd);
        return this.exec(ChaineJava.$new('echo'));
      }
      return this.exec(cmd);
    };

    Exec.exec.overload('[Ljava.lang.String;').implementation = function (arr) {
      const js = arr ? Array.from(arr) : [];
      if (commandeSuspecte(js)) {
        console.log('[+] Runtime.exec bloque:', js.join(' '));
        const repl = TableauChaines.$new(1);
        repl[0] = ChaineJava.$new('echo');
        return this.exec(repl);
      }
      return this.exec(arr);
    };

    console.log('[+] Hooks Runtime.exec actifs');
  } catch (e) { console.log('[-] Echec hooks Runtime.exec:', e); }

  // --- Bloquer System.exit pour empecher fermeture forcee ---
  try {
    const Systeme = Java.use('java.lang.System');
    Systeme.exit.implementation = function(code) {
      console.log('[+] System.exit bloque, code:', code);
    };
    console.log('[+] Hook System.exit actif');
  } catch(e) { console.log('[-] Echec hook System.exit:', e); }

  // --- Bloquer AlertDialog pour empecher popup Root detected ---
  try {
    const Dialogue = Java.use('android.app.AlertDialog');
    Dialogue.show.implementation = function() {
      console.log('[+] AlertDialog.show bloque');
    };
    console.log('[+] Hook AlertDialog actif');
  } catch(e) { console.log('[-] Echec hook AlertDialog:', e); }

  console.log('[+] Bypass couche Java installe avec succes');
});
