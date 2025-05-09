# Aqua - HackMyVM Writeup

![Aqua VM Icon](Aqua.png)

Dieses Repository enthält das Writeup für die HackMyVM-Maschine "Aqua" (Schwierigkeitsgrad: Medium), erstellt von DarkSpirit. Ziel war es, initialen Zugriff auf die virtuelle Maschine zu erlangen und die Berechtigungen bis zum Root-Benutzer zu eskalieren.

## VM-Informationen

*   **VM Name:** Aqua
*   **Plattform:** HackMyVM
*   **Autor der VM:** DarkSpirit
*   **Schwierigkeitsgrad:** Medium
*   **Link zur VM:** [https://hackmyvm.eu/machines/machine.php?vm=Aqua](https://hackmyvm.eu/machines/machine.php?vm=Aqua)

## Writeup-Informationen

*   **Autor des Writeups:** Ben C.
*   **Datum des Berichts:** 03. Oktober 2021
*   **Link zum Original-Writeup (GitHub Pages):** [https://alientec1908.github.io/Aqua_HackMyVM_Medium/](https://alientec1908.github.io/Aqua_HackMyVM_Medium/)

## Kurzübersicht des Angriffspfads

Der Angriff auf die Aqua-Maschine umfasste mehrere komplexe Schritte:

1.  **Reconnaissance:**
    *   Identifizierung der Ziel-IP (`192.168.2.127`) mittels `arp-scan`.
    *   Ein `nmap`-Scan offenbarte offene Ports: SSH (22, OpenSSH 7.6p1), HTTP (80, Apache 2.4.29, Titel "Todo sobre el Agua"), AJP13 (8009, Apache Jserv), und HTTP (8080, Apache Tomcat 8.5.5). Port 21 (FTP) wurde als `filtered` erkannt.
2.  **Web Enumeration & Git Dump:**
    *   Die `robots.txt` auf Port 80 verwies auf das Verzeichnis `/SuperCMS/`.
    *   `gobuster` entdeckte ein exponiertes `.git`-Verzeichnis unter `/SuperCMS/.git/`.
    *   Mittels `git-dumper.py` wurde das gesamte Git-Repository heruntergeladen.
3.  **Port Knocking Sequenz Entdeckung:**
    *   Die Analyse der Git-Historie (`git show`) offenbarte in einer älteren Version der Datei `knocking_on_Atlantis_door.txt` die Port-Knocking-Sequenz `1100, 800, 666`, um den FTP-Port zu öffnen.
4.  **FTP Anonymous & Backup Analysis:**
    *   Nach erfolgreichem Port Knocking (vermutlich mit `knock`) war anonymer FTP-Zugriff auf Port 21 möglich.
    *   Im Verzeichnis `/pub` wurde die Datei `.backup.zip` gefunden und heruntergeladen.
    *   Die ZIP-Datei wurde mit `7za` und dem abgeleiteten Passwort `H2O` (Hinweis "1=2 = password_zip" und Webseitenthema "Wasser") entpackt.
    *   Die entpackte Datei `tomcat-users.xml` enthielt die Tomcat-Manager-Zugangsdaten `aquaMan:P4st3lM4n` für die Rollen `manager-gui, admin-gui`.
5.  **Initial Access (Tomcat RCE):**
    *   Mit `msfvenom` wurde eine `reverse.war`-Datei (Java/JSP Reverse Shell) erstellt.
    *   Diese WAR-Datei wurde über den Tomcat Manager (`http://192.168.2.127:8080/manager/html`) mit den gefundenen Zugangsdaten hochgeladen.
    *   Ein `nc`-Listener wurde gestartet, und der Aufruf der deployten WAR-Anwendung (`/hack/`) triggerte eine Reverse Shell als Benutzer `tomcat`. Die Shell wurde anschließend stabilisiert.
6.  **Lateral Movement (Memcached Leak - tomcat zu tridente):**
    *   `netstat` (impliziert) zeigte einen laufenden Memcached-Dienst auf `localhost:11211`.
    *   Mittels `telnet` zu Memcached und Abfrage der gespeicherten Items (`stats items`, `stats cachedump`, `get`) wurden die Zugangsdaten `tridente:N3ptun0D10sd3lM4r$` extrahiert.
    *   Ein Wechsel zum Benutzer `tridente` gelang mit `su tridente` und dem gefundenen Passwort.
    *   Die User-Flag (`/home/tridente/user.txt`) wurde gelesen.
7.  **Privilege Escalation (tridente zu root):**
    *   Die Binary `/bin/bash` wurde nach `/home/tridente/find` kopiert.
    *   Eine (implizierte) unsichere `sudo`-Regel erlaubte `tridente` die Ausführung von `/home/tridente/find` (oder einer manipulierbaren `find`-Pfadangabe) als `root`.
    *   Durch Ausführen von `sudo -u root /home/tridente/find -p` (mit dem Passwort von `tridente`) wurde eine Root-Shell erlangt, da `/home/tridente/find` nun eine Bash-Shell war.
8.  **Root Flag Decryption:**
    *   Im Root-Verzeichnis (`/root/`) wurde die verschlüsselte Datei `root.txt.gpg` gefunden.
    *   Die Datei wurde vom Zielsystem heruntergeladen (via Python HTTP-Server).
    *   `gpg2john` extrahierte den Passwort-Hash aus `root.txt.gpg`.
    *   `john` knackte den Hash mit der `rockyou.txt`-Wortliste und fand das Passwort `arthur`.
    *   Auf dem Zielsystem wurde `root.txt.gpg` mit `gpg` und dem Passwort `arthur` entschlüsselt und die Root-Flag ausgelesen.

## Verwendete Tools

*   `arp-scan`
*   `nmap`
*   `curl`
*   `echo`
*   `base64`
*   `gobuster`
*   `git-dumper.py` (als `git_dumper.py` im Text)
*   `git`
*   `knock` (impliziert für Port Knocking)
*   `ftp`
*   `7za`
*   `cat`
*   `msfvenom`
*   `mv`
*   `nc` (netcat)
*   `python3`
*   `export`
*   `stty`
*   `netstat`
*   `telnet`
*   `su`
*   `cd`
*   `ls`
*   `mkdir`
*   `ssh`
*   `cp`
*   `sudo`
*   `wget`
*   `gpg2john`
*   `john`
*   `gpg`
*   `id`

## Identifizierte Schwachstellen (Zusammenfassung)

*   **Exponiertes `.git`-Verzeichnis:** Erlaubte das Herunterladen des Quellcodes und der Versionshistorie, was zur Entdeckung der Port-Knocking-Sequenz führte.
*   **Auffindbare Port-Knocking-Sequenz:** Die Sequenz wurde in der Git-Historie gefunden, was den Schutzmechanismus aushebelte.
*   **Anonymer FTP-Zugriff:** Nach dem Port Knocking war anonymer Zugriff möglich, der zum Download einer sensiblen Backup-Datei führte.
*   **Schwaches Passwort für Backup-Archiv:** Die ZIP-Datei war mit einem leicht erratbaren Passwort (`H2O`) geschützt.
*   **Tomcat-Manager-Zugangsdaten im Backup:** Die Datei `tomcat-users.xml` im Backup enthielt gültige Admin-Zugangsdaten.
*   **Tomcat Remote Code Execution:** Durch den Zugriff auf den Tomcat-Manager konnte eine bösartige WAR-Datei hochgeladen und eine Reverse Shell erlangt werden.
*   **Unauthentifizierte Memcached-Instanz:** Memcached lief auf localhost ohne Authentifizierung und enthielt Klartext-Zugangsdaten für den Benutzer `tridente`.
*   **Unsichere `sudo`-Konfiguration:** Eine `sudo`-Regel erlaubte dem Benutzer `tridente` die Ausführung einer Datei (`find`) aus seinem Home-Verzeichnis als `root`, was durch Ersetzen der Datei mit einer Bash-Shell zur Privilegieneskalation führte.
*   **Schwaches GPG-Passwort:** Das Passwort zur Verschlüsselung der Root-Flag konnte mittels `rockyou.txt` geknackt werden.

## Flags

*   **User Flag (`/home/tridente/user.txt`):** `f506a6ee37275430ac07caa95914aeba`
*   **Root Flag (`/root/root.txt`):** `e16957fbc9202932b1dc7fe3e10a197e`

---

**Wichtiger Hinweis:** Dieses Dokument und die darin enthaltenen Informationen dienen ausschließlich zu Bildungs- und Forschungszwecken im Bereich der Cybersicherheit. Die beschriebenen Techniken und Werkzeuge sollten nur in legalen und autorisierten Umgebungen (z.B. eigenen Testlaboren, CTFs oder mit expliziter Genehmigung) angewendet werden. Das unbefugte Eindringen in fremde Computersysteme ist eine Straftat und kann rechtliche Konsequenzen nach sich ziehen.

---
*Bericht von Ben C. - Cyber Security Reports*
