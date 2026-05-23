# android-root-bypass-frida-native-hooks

## LAB 14 — Bypass Root Detection : Techniques Dynamiques avec Frida, Objection et Hooks Natifs

**Cours:** Sécurité des applications mobiles  
**Niveau:** Débutant  
**Plateforme:** Windows 10 + Android Emulator API 30  
**Outils:** Frida 16.1.3 + Objection 1.11.0  
**Dossier de travail:** F:\lab14sec

---

## Objectif

Ce lab consolide les techniques des LAB 12 et 13 en ajoutant une couche
supplémentaire : les hooks natifs C/C++. L'objectif est de comprendre que
la détection de root ne se limite pas à la couche Java — certaines apps
utilisent des appels système libc (open, stat, access) pour détecter su
et busybox à un niveau plus bas.

L'app cible est OWASP UnCrackable Level 1. Le bypass est validé quand
l'app s'ouvre sans le popup "Root detected! This is unacceptable."

---

## Environnement

| Composant | Version |
|-----------|---------|
| OS | Windows 10 (10.0.19045) |
| Python | 3.12.10 |
| Frida PC | 16.1.3 |
| frida-server | 16.1.3 (android-x86_64) |
| Objection | 1.11.0 |
| ADB | 1.0.41 (37.0.0) |
| Emulateur | Android API 30 x86_64 |
| App cible | owasp.mstg.uncrackable1 |

---

## Structure du dossier de travail

```
F:\lab14sec
|-- bypass_java.js      # Hooks couche Java
|-- bypass_native.js    # Hooks couche native C/C++
```
---

## Ce que ce lab apporte de nouveau par rapport aux LAB 12 et 13

Les LAB 12 et 13 couvraient uniquement la couche Java. Ce lab introduit
les hooks natifs — quand une app Android utilise du code C/C++ pour
appeler directement les fonctions libc comme open(), stat(), access() ou
openat() sur des chemins comme /system/bin/su, les hooks Java ne suffisent
plus. Il faut intercepter ces appels au niveau du système.

frida-trace est utilisé ici pour observer en temps réel quels appels natifs
l'app déclenche, ce qui permet d'adapter la liste des chemins bloqués.

---

## Script bypass_java.js

Ce script neutralise toutes les vérifications de root côté Java. Il a été
écrit avec des noms de variables en français pour le distinguer des scripts
génériques trouvés en ligne.

Points clés par rapport au LAB 12 :
- Ajout du hook System.exit pour empêcher la fermeture forcée de l'app
- Ajout du hook AlertDialog.show pour bloquer le popup avant affichage
- Sans ces deux hooks, l'app affichait le popup même avec Build.TAGS et
  File.exists hookés

```javascript
// Variables renommées en français pour personnalisation
const cheminsSuspects = [ ... ];
const InfoBuild = Java.use('android.os.Build');      // au lieu de Build
const FichierJava = Java.use('java.io.File');         // au lieu de File
const Exec = Java.use('java.lang.Runtime');           // au lieu de Runtime
const Systeme = Java.use('java.lang.System');         // hook System.exit
const Dialogue = Java.use('android.app.AlertDialog'); // hook popup
```

Commande d'exécution :
```powershell
frida -U -f owasp.mstg.uncrackable1 -l F:\lab14sec\bypass_java.js
```

Logs obtenus :
```
[+] Build.TAGS force en release-keys
[*] RootBeer absent sur cette app
[+] Hooks Runtime.exec actifs
[+] Hook System.exit actif
[+] Hook AlertDialog actif
[+] Bypass couche Java installe avec succes
[+] File.exists bloque pour: /system/bin/su
[+] File.exists bloque pour: /system/xbin/su
[+] AlertDialog.show bloque
```
<img width="901" height="495" alt="image" src="https://github.com/user-attachments/assets/a6136444-c358-4ae0-9cc4-93b0db7970bd" />

---

## Observation importante — premier test sans System.exit et AlertDialog

Lors du premier test avec uniquement les hooks Build.TAGS, File.exists et
Runtime.exec, le popup "Root detected" apparaissait encore. Les logs
montraient pourtant que File.exists était bien intercepté. L'app utilisait
un chemin de détection supplémentaire via AlertDialog et System.exit.

Après ajout des deux hooks manquants, le bypass était complet.

---

## Script bypass_native.js

Ce script intercepte les appels libc au niveau natif. La fonction
installerHookLibc() centralise la logique pour éviter la répétition.

```javascript
// Nommage personnalisé
function cheminEstSuspect(pointeurChemin) { ... }
function installerHookLibc(nomFonction, indexArgChemin) { ... }

installerHookLibc('open', 0);
installerHookLibc('openat', 1);
installerHookLibc('access', 0);
installerHookLibc('stat', 0);
installerHookLibc('lstat', 0);
```

---

## Bypass combiné Java + Natif

```powershell
adb shell am force-stop owasp.mstg.uncrackable1
frida -U -f owasp.mstg.uncrackable1 -l F:\lab14sec\bypass_java.js -l F:\lab14sec\bypass_native.js
```

Logs obtenus :
```
[+] Hook natif installe sur: open
[+] Hook natif installe sur: openat
[+] Hook natif installe sur: access
[+] Hook natif installe sur: stat
[+] Hook natif installe sur: lstat
[+] Hooks natifs C/C++ installes avec succes
[+] Build.TAGS force en release-keys
[+] Hook System.exit actif
[+] Hook AlertDialog actif
[+] File.exists bloque pour: /system/bin/su
[+] File.exists bloque pour: /system/xbin/su
[+] AlertDialog.show bloque
```
<img width="976" height="607" alt="image" src="https://github.com/user-attachments/assets/a83326e9-bbda-4e12-ab71-52b9160cb0da" />

---

## Observation des appels natifs avec frida-trace

frida-trace permet de voir en temps réel quels appels natifs l'app
déclenche. On l'utilise après avoir spawné l'app avec le bypass pour
qu'elle reste ouverte.

```powershell
# Terminal 1 — spawner avec bypass
frida -U -f owasp.mstg.uncrackable1 -l F:\lab14sec\bypass_java.js -l F:\lab14sec\bypass_native.js

# Terminal 2 — récupérer le PID
adb shell pidof owasp.mstg.uncrackable1
# Résultat: 3741

# Terminal 2 — lancer frida-trace
frida-trace -U -p 3741 -i open -i access -i stat -i openat
```

Résultat observé après interaction avec l'app :
```
31160 ms  open()
31160 ms  stat()
```

L'app appelle effectivement open() et stat() — confirmant que les hooks
natifs dans bypass_native.js sont nécessaires pour un bypass complet.

<img width="986" height="392" alt="image" src="https://github.com/user-attachments/assets/d8ed03e0-a443-4358-b63e-55bb0db17c11" />

---

## Pourquoi deux terminaux sont nécessaires

frida-trace ne peut pas s'attacher à une app qui se ferme immédiatement.
Sans le bypass actif dans le terminal 1, l'app détecte le root et se ferme
avant que frida-trace puisse l'instrumenter. Le terminal 1 maintient l'app
ouverte pendant que le terminal 2 observe les appels natifs.

---

## Comparaison des trois approches vues dans les labs

| Approche | Avantage | Limite |
|----------|----------|--------|
| Frida spawn + bypass_java.js | Contrôle total, injection précoce | Script à écrire manuellement |
| Objection android root disable | Une seule commande, rapide | Attach uniquement, pas de spawn fiable en v1.11.0 |
| Frida + bypass_java + bypass_native | Couvre Java et C/C++ | Deux scripts à maintenir |

---

## Références

- Frida: https://frida.re
- Objection: https://github.com/sensepost/objection
- OWASP MASTG: https://mas.owasp.org/MASTG
- Frida Releases: https://github.com/frida/frida/releases
- Android Platform Tools: https://developer.android.com/tools/releases/platform-tools
