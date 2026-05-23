// ============================================================
// bypass_native.js — Lab14 Hooks Natifs C/C++
// Auteur: test sur owasp.mstg.uncrackable1
// Emulateur: Android API 30 x86_64
// Objectif: bloquer les appels libc vers chemins suspects
// ============================================================

const cheminsSuspectsNatif = [
  '/system/bin/su', '/system/xbin/su', '/sbin/su', '/system/su',
  '/system/bin/busybox', '/system/xbin/busybox'
];

function cheminEstSuspect(pointeurChemin) {
  try {
    const chemin = pointeurChemin.readCString();
    if (!chemin) return false;
    return cheminsSuspectsNatif.indexOf(chemin) !== -1
      || chemin.includes('/proc/mounts')
      || chemin.includes('/proc/self/mounts');
  } catch(_) { return false; }
}

function installerHookLibc(nomFonction, indexArgChemin) {
  const adresse = Module.findExportByName('libc.so', nomFonction)
                  || Module.findExportByName(null, nomFonction);

  if (!adresse) {
    console.log('[*] Fonction introuvable dans libc:', nomFonction);
    return;
  }

  Interceptor.attach(adresse, {
    onEnter(args) {
      const arg = indexArgChemin >= 0 ? args[indexArgChemin] : null;
      if (arg && cheminEstSuspect(arg)) {
        this.bloquer = true;
        this.cheminDetecte = arg.readCString();
      }
    },
    onLeave(valRetour) {
      if (this.bloquer) {
        console.log('[+] Appel natif bloque:', nomFonction, '->', this.cheminDetecte);
        valRetour.replace(ptr(-1));
      }
    }
  });

  console.log('[+] Hook natif installe sur:', nomFonction);
}

// Bloquer les fonctions libc couramment utilisees pour detecter root
installerHookLibc('open', 0);
installerHookLibc('openat', 1);
installerHookLibc('access', 0);
installerHookLibc('stat', 0);
installerHookLibc('lstat', 0);

console.log('[+] Hooks natifs C/C++ installes avec succes');
