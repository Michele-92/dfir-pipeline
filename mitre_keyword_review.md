# MITRE ATT&CK Linux — Keyword Review

**Anleitung:**
1. Lies die offizielle MITRE-Beschreibung jeder Technik
2. Trage in der Spalte "Keywords (manuell)" konkrete Linux-Befehle/
   Strings ein die diese Technik in Log-Dateien hinterlässt
3. Setze in "Aufnehmen?" ein Ja oder Nein
4. Gib die ausgefüllte Datei zurück zur Implementierung

Bereits implementiert: 26 T-Nummern  
Zu reviewen: 146 T-Nummern  

---

## CREDENTIAL ACCESS

### T1003.005 — Cached Domain Credentials

**Taktik:** credential-access  
**MITRE Beschreibung (offiziell):**  
> Adversaries may attempt to access cached domain credentials used to allow authentication to occur in the event a domain controller is unavailable.(Citation: Microsoft - Cached Creds)

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

### T1003.007 — Proc Filesystem

**Taktik:** credential-access  
**MITRE Beschreibung (offiziell):**  
> Adversaries may gather credentials from the proc filesystem or `/proc`. The proc filesystem is a pseudo-filesystem used as an interface to kernel data structures for Linux based systems managing virtual memory. For each process, the `/proc/<PID>/maps` file shows how memory is mapped within the process’s virtual address space. And `/proc/<PID>/mem`, exposed for debugging purposes, provides access t...

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

## DISCOVERY

### T1007 — System Service Discovery

**Taktik:** discovery  
**MITRE Beschreibung (offiziell):**  
> Adversaries may try to gather information about registered local system services. Adversaries may obtain information about services using tools as well as OS utility commands such as <code>sc query</code>, <code>tasklist /svc</code>, <code>systemctl --type=service</code>, and <code>net start</code>. Adversaries may also gather information about schedule tasks via commands such as `schtasks` on Win...

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

## LATERAL MOVEMENT

### T1021 — Remote Services

**Taktik:** lateral-movement  
**MITRE Beschreibung (offiziell):**  
> Adversaries may use [Valid Accounts](https://attack.mitre.org/techniques/T1078) to log into a service that accepts remote connections, such as telnet, SSH, and VNC. The adversary may then perform actions as the logged-on user.

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

### T1021.005 — VNC

**Taktik:** lateral-movement  
**MITRE Beschreibung (offiziell):**  
> Adversaries may use [Valid Accounts](https://attack.mitre.org/techniques/T1078) to remotely control machines using Virtual Network Computing (VNC).  VNC is a platform-independent desktop sharing system that uses the RFB (“remote framebuffer”) protocol to enable users to remotely control another computer’s display by relaying the screen, mouse, and keyboard inputs over the network.(Citation: The Re...

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

## DISCOVERY

### T1033 — System Owner/User Discovery

**Taktik:** discovery  
**MITRE Beschreibung (offiziell):**  
> Adversaries may attempt to identify the primary user, currently logged in user, set of users that commonly uses a system, or whether a user is actively using the system. They may do this, for example, by retrieving account usernames or by using [OS Credential Dumping](https://attack.mitre.org/techniques/T1003). The information may be collected in a number of different ways using other Discovery te...

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

## DEFENSE EVASION

### T1036 — Masquerading

**Taktik:** defense-evasion  
**MITRE Beschreibung (offiziell):**  
> Adversaries may attempt to manipulate features of their artifacts to make them appear legitimate or benign to users and/or security tools. Masquerading occurs when the name or location of an object, legitimate or malicious, is manipulated or abused for the sake of evading defenses and observation. This may include manipulating file metadata, tricking users into misidentifying the file type, and gi...

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

### T1036.002 — Right-to-Left Override

**Taktik:** defense-evasion  
**MITRE Beschreibung (offiziell):**  
> Adversaries may abuse the right-to-left override (RTLO or RLO) character (U+202E) to disguise a string and/or file name to make it appear benign. RTLO is a non-printing Unicode character that causes the text that follows it to be displayed in reverse. For example, a Windows screensaver executable named <code>March 25 \u202Excod.scr</code> will display as <code>March 25 rcs.docx</code>. A JavaScrip...

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

### T1036.003 — Rename Legitimate Utilities

**Taktik:** defense-evasion  
**MITRE Beschreibung (offiziell):**  
> Adversaries may rename legitimate / system utilities to try to evade security mechanisms concerning the usage of those utilities. Security monitoring and control mechanisms may be in place for legitimate utilities adversaries are capable of abusing, including both built-in binaries and tools such as PSExec, AutoHotKey, and IronPython.(Citation: LOLBAS Main Site)(Citation: Huntress Python Malware 2...

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

### T1036.004 — Masquerade Task or Service

**Taktik:** defense-evasion  
**MITRE Beschreibung (offiziell):**  
> Adversaries may attempt to manipulate the name of a task or service to make it appear legitimate or benign. Tasks/services executed by the Task Scheduler or systemd will typically be given a name and/or description.(Citation: TechNet Schtasks)(Citation: Systemd Service Units) Windows services will have a service name as well as a display name. Many benign tasks and services exist that have commonl...

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

### T1036.005 — Match Legitimate Resource Name or Location

**Taktik:** defense-evasion  
**MITRE Beschreibung (offiziell):**  
> Adversaries may match or approximate the name or location of legitimate files, Registry keys, or other resources when naming/placing them. This is done for the sake of evading defenses and observation.

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

### T1036.006 — Space after Filename

**Taktik:** defense-evasion  
**MITRE Beschreibung (offiziell):**  
> Adversaries can hide a program's true filetype by changing the extension of a file. With certain file types (specifically this does not work with .app extensions), appending a space to the end of a filename will change how the file is processed by the operating system.

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

### T1036.008 — Masquerade File Type

**Taktik:** defense-evasion  
**MITRE Beschreibung (offiziell):**  
> Adversaries may masquerade malicious payloads as legitimate files through changes to the payload's formatting, including the file’s signature, extension, icon, and contents. Various file types have a typical standard format, including how they are encoded and organized. For example, a file’s signature (also known as header or magic bytes) is the beginning bytes of a file and is often used to ident...

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

### T1036.009 — Break Process Trees

**Taktik:** defense-evasion  
**MITRE Beschreibung (offiziell):**  
> An adversary may attempt to evade process tree-based analysis by modifying executed malware's parent process ID (PPID). If endpoint protection software leverages the “parent-child" relationship for detection, breaking this relationship could result in the adversary’s behavior not being associated with previous process tree activity. On Unix-based systems breaking this process tree is common practi...

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

### T1036.010 — Masquerade Account Name

**Taktik:** defense-evasion  
**MITRE Beschreibung (offiziell):**  
> Adversaries may match or approximate the names of legitimate accounts to make newly created ones appear benign. This will typically occur during [Create Account](https://attack.mitre.org/techniques/T1136), although accounts may also be renamed at a later date. This may also coincide with [Account Access Removal](https://attack.mitre.org/techniques/T1531) if the actor first deletes an account befor...

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

### T1036.011 — Overwrite Process Arguments

**Taktik:** defense-evasion  
**MITRE Beschreibung (offiziell):**  
> Adversaries may modify a process's in-memory arguments to change its name in order to appear as a legitimate or benign process. On Linux, the operating system stores command-line arguments in the process’s stack and passes them to the `main()` function as the `argv` array. The first element, `argv[0]`, typically contains the process name or path - by default, the command used to actually start the...

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

### T1036.012 — Browser Fingerprint

**Taktik:** defense-evasion  
**MITRE Beschreibung (offiziell):**  
> Adversaries may attempt to blend in with legitimate traffic by spoofing browser and system attributes like operating system, system language, platform, user-agent string, resolution, time zone, etc.  The HTTP User-Agent request header is a string that lets servers and network peers identify the application, operating system, vendor, and/or version of the requesting user agent.(Citation: Mozilla Us...

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

## PERSISTENCE

### T1037 — Boot or Logon Initialization Scripts

**Taktik:** persistence, privilege-escalation  
**MITRE Beschreibung (offiziell):**  
> Adversaries may use scripts automatically executed at boot or logon initialization to establish persistence.(Citation: Mandiant APT29 Eye Spy Email Nov 22)(Citation: Anomali Rocke March 2019) Initialization scripts can be used to perform administrative functions, which may often execute other programs or send information to an internal logging server. These scripts can vary based on operating syst...

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

### T1037.004 — RC Scripts

**Taktik:** persistence, privilege-escalation  
**MITRE Beschreibung (offiziell):**  
> Adversaries may establish persistence by modifying RC scripts, which are executed during a Unix-like system’s startup. These files allow system administrators to map and start custom services at startup for different run levels. RC scripts require root privileges to modify.

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

## DISCOVERY

### T1049 — System Network Connections Discovery

**Taktik:** discovery  
**MITRE Beschreibung (offiziell):**  
> Adversaries may attempt to get a listing of network connections to or from the compromised system they are currently accessing or from remote systems by querying for information over the network.

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

## EXECUTION

### T1053 — Scheduled Task/Job

**Taktik:** execution, persistence, privilege-escalation  
**MITRE Beschreibung (offiziell):**  
> Adversaries may abuse task scheduling functionality to facilitate initial or recurring execution of malicious code. Utilities exist within all major operating systems to schedule programs or scripts to be executed at a specified date and time. A task can also be scheduled on a remote system, provided the proper authentication is met (ex: RPC and file and printer sharing in Windows environments). S...

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

### T1053.001 — At (Linux)

**Taktik:** execution, persistence, privilege-escalation  
**MITRE Beschreibung (offiziell):**  
> Adversaries may abuse the [at](https://attack.mitre.org/software/S0110) utility to perform task scheduling for initial, recurring, or future execution of malicious code. The [at](https://attack.mitre.org/software/S0110) command within Linux operating systems enables administrators to schedule tasks.(Citation: Kifarunix - Task Scheduling in Linux)

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

### T1053.002 — At

**Taktik:** execution, persistence, privilege-escalation  
**MITRE Beschreibung (offiziell):**  
> Adversaries may abuse the [at](https://attack.mitre.org/software/S0110) utility to perform task scheduling for initial or recurring execution of malicious code. The [at](https://attack.mitre.org/software/S0110) utility exists as an executable within Windows, Linux, and macOS for scheduling tasks at a specified time and date. Although deprecated in favor of [Scheduled Task](https://attack.mitre.org...

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

## DEFENSE EVASION

### T1055 — Process Injection

**Taktik:** defense-evasion, privilege-escalation  
**MITRE Beschreibung (offiziell):**  
> Adversaries may inject code into processes in order to evade process-based defenses as well as possibly elevate privileges. Process injection is a method of executing arbitrary code in the address space of a separate live process. Running code in the context of another process may allow access to the process's memory, system/network resources, and possibly elevated privileges. Execution via proces...

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

### T1055.008 — Ptrace System Calls

**Taktik:** defense-evasion, privilege-escalation  
**MITRE Beschreibung (offiziell):**  
> Adversaries may inject malicious code into processes via ptrace (process trace) system calls in order to evade process-based defenses as well as possibly elevate privileges. Ptrace system call injection is a method of executing arbitrary code in the address space of a separate live process.

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

### T1055.009 — Proc Memory

**Taktik:** defense-evasion, privilege-escalation  
**MITRE Beschreibung (offiziell):**  
> Adversaries may inject malicious code into processes via the /proc filesystem in order to evade process-based defenses as well as possibly elevate privileges. Proc memory injection is a method of executing arbitrary code in the address space of a separate live process.

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

### T1055.014 — VDSO Hijacking

**Taktik:** defense-evasion, privilege-escalation  
**MITRE Beschreibung (offiziell):**  
> Adversaries may inject malicious code into processes via VDSO hijacking in order to evade process-based defenses as well as possibly elevate privileges. Virtual dynamic shared object (vdso) hijacking is a method of executing arbitrary code in the address space of a separate live process.

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

## COLLECTION

### T1056 — Input Capture

**Taktik:** collection, credential-access  
**MITRE Beschreibung (offiziell):**  
> Adversaries may use methods of capturing user input to obtain credentials or collect information. During normal system usage, users often provide credentials to various different locations, such as login pages/portals or system dialog boxes. Input capture mechanisms may be transparent to the user (e.g. [Credential API Hooking](https://attack.mitre.org/techniques/T1056/004)) or rely on deceiving th...

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

### T1056.001 — Keylogging

**Taktik:** collection, credential-access  
**MITRE Beschreibung (offiziell):**  
> Adversaries may log user keystrokes to intercept credentials as the user types them. Keylogging is likely to be used to acquire credentials for new access opportunities when [OS Credential Dumping](https://attack.mitre.org/techniques/T1003) efforts are not effective, and may require an adversary to intercept keystrokes on a system for a substantial period of time before credentials can be successf...

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

### T1056.002 — GUI Input Capture

**Taktik:** collection, credential-access  
**MITRE Beschreibung (offiziell):**  
> Adversaries may mimic common operating system GUI components to prompt users for credentials with a seemingly legitimate prompt. When programs are executed that need additional privileges than are present in the current user context, it is common for the operating system to prompt the user for proper credentials to authorize the elevated privileges for the task (ex: [Bypass User Account Control](h...

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

### T1056.003 — Web Portal Capture

**Taktik:** collection, credential-access  
**MITRE Beschreibung (offiziell):**  
> Adversaries may install code on externally facing portals, such as a VPN login page, to capture and transmit credentials of users who attempt to log into the service. For example, a compromised login page may log provided user credentials before logging the user in to the service.

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

### T1056.004 — Credential API Hooking

**Taktik:** collection, credential-access  
**MITRE Beschreibung (offiziell):**  
> Adversaries may hook into Windows application programming interface (API) functions and Linux system functions to collect user credentials. Malicious hooking mechanisms may capture API or function calls that include parameters that reveal user authentication credentials.(Citation: Microsoft TrojanSpy:Win32/Ursnif.gen!I Sept 2017) Unlike [Keylogging](https://attack.mitre.org/techniques/T1056/001), ...

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

## DISCOVERY

### T1057 — Process Discovery

**Taktik:** discovery  
**MITRE Beschreibung (offiziell):**  
> Adversaries may attempt to get information about running processes on a system. Information obtained could be used to gain an understanding of common software/applications running on systems within the network. Administrator or otherwise elevated access may provide better process details. Adversaries may use the information from [Process Discovery](https://attack.mitre.org/techniques/T1057) during...

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

## EXECUTION

### T1059 — Command and Scripting Interpreter

**Taktik:** execution  
**MITRE Beschreibung (offiziell):**  
> Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries. These interfaces and languages provide ways of interacting with computer systems and are a common feature across many different platforms. Most systems come with some built-in command-line interface and scripting capabilities, for example, macOS and Linux distributions include some flavor of [Unix Shel...

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

### T1059.005 — Visual Basic

**Taktik:** execution  
**MITRE Beschreibung (offiziell):**  
> Adversaries may abuse Visual Basic (VB) for execution. VB is a programming language created by Microsoft with interoperability with many Windows technologies such as [Component Object Model](https://attack.mitre.org/techniques/T1559/001) and the [Native API](https://attack.mitre.org/techniques/T1106) through the Windows API. Although tagged as legacy with no planned future evolutions, VB is integr...

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

### T1059.007 — JavaScript

**Taktik:** execution  
**MITRE Beschreibung (offiziell):**  
> Adversaries may abuse various implementations of JavaScript for execution. JavaScript (JS) is a platform-independent scripting language (compiled just-in-time at runtime) commonly associated with scripts in webpages, though JS can be executed in runtime environments outside the browser.(Citation: NodeJS)

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

### T1059.011 — Lua

**Taktik:** execution  
**MITRE Beschreibung (offiziell):**  
> Adversaries may abuse Lua commands and scripts for execution. Lua is a cross-platform scripting and programming language primarily designed for embedded use in applications. Lua can be executed on the command-line (through the stand-alone lua interpreter), via scripts (<code>.lua</code>), or from Lua-embedded programs (through the <code>struct lua_State</code>).(Citation: Lua main page)(Citation: ...

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

## PRIVILEGE ESCALATION

### T1068 — Exploitation for Privilege Escalation

**Taktik:** privilege-escalation  
**MITRE Beschreibung (offiziell):**  
> Adversaries may exploit software vulnerabilities in an attempt to elevate privileges. Exploitation of a software vulnerability occurs when an adversary takes advantage of a programming error in a program, service, or within the operating system software or kernel itself to execute adversary-controlled code. Security constructs such as permission levels will often hinder access to information and u...

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

## DISCOVERY

### T1069 — Permission Groups Discovery

**Taktik:** discovery  
**MITRE Beschreibung (offiziell):**  
> Adversaries may attempt to discover group and permission settings. This information can help adversaries determine which user accounts and groups are available, the membership of users in particular groups, and which users and groups have elevated permissions.

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

### T1069.001 — Local Groups

**Taktik:** discovery  
**MITRE Beschreibung (offiziell):**  
> Adversaries may attempt to find local system groups and permission settings. The knowledge of local system permission groups can help adversaries determine which groups exist and which users belong to a particular group. Adversaries may use this information to determine which users have elevated permissions, such as the users found within the local administrators group.

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

### T1069.002 — Domain Groups

**Taktik:** discovery  
**MITRE Beschreibung (offiziell):**  
> Adversaries may attempt to find domain-level groups and permission settings. The knowledge of domain-level permission groups can help adversaries determine which groups exist and which users belong to a particular group. Adversaries may use this information to determine which users have elevated permissions, such as domain administrators.

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

## DEFENSE EVASION

### T1070 — Indicator Removal

**Taktik:** defense-evasion  
**MITRE Beschreibung (offiziell):**  
> Adversaries may delete or modify artifacts generated within systems to remove evidence of their presence or hinder defenses. Various artifacts may be created by an adversary or something that can be attributed to an adversary’s actions. Typically these artifacts are used as defensive indicators related to monitored events, such as strings from downloaded files, logs that are generated from user ac...

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

### T1070.004 — File Deletion

**Taktik:** defense-evasion  
**MITRE Beschreibung (offiziell):**  
> Adversaries may delete files left behind by the actions of their intrusion activity. Malware, tools, or other non-native files dropped or created on a system by an adversary (ex: [Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105)) may leave traces to indicate to what was done within a network and how. Removal of these files can occur during an intrusion, or as part of a post-intrus...

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

### T1070.006 — Timestomp

**Taktik:** defense-evasion  
**MITRE Beschreibung (offiziell):**  
> Adversaries may modify file time attributes to hide new files or changes to existing files. Timestomping is a technique that modifies the timestamps of a file (the modify, access, create, and change times), often to mimic files that are in the same folder and blend malicious files with legitimate files.

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

### T1070.007 — Clear Network Connection History and Configurations

**Taktik:** defense-evasion  
**MITRE Beschreibung (offiziell):**  
> Adversaries may clear or remove evidence of malicious network connections in order to clean up traces of their operations. Configuration settings as well as various artifacts that highlight connection history may be created on a system and/or in application logs from behaviors that require network connections, such as [Remote Services](https://attack.mitre.org/techniques/T1021) or [External Remote...

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

### T1070.008 — Clear Mailbox Data

**Taktik:** defense-evasion  
**MITRE Beschreibung (offiziell):**  
> Adversaries may modify mail and mail application data to remove evidence of their activity. Email applications allow users and other programs to export and delete mailbox data via command line tools or use of APIs. Mail application data can be emails, email metadata, or logs generated by the application or operating system, such as export requests.

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

### T1070.009 — Clear Persistence

**Taktik:** defense-evasion  
**MITRE Beschreibung (offiziell):**  
> Adversaries may clear artifacts associated with previously established persistence on a host system to remove evidence of their activity. This may involve various actions, such as removing services, deleting executables, [Modify Registry](https://attack.mitre.org/techniques/T1112), [Plist File Modification](https://attack.mitre.org/techniques/T1647), or other methods of cleanup to prevent defender...

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

### T1070.010 — Relocate Malware

**Taktik:** defense-evasion  
**MITRE Beschreibung (offiziell):**  
> Once a payload is delivered, adversaries may reproduce copies of the same malware on the victim system to remove evidence of their presence and/or avoid defenses. Copying malware payloads to new locations may also be combined with [File Deletion](https://attack.mitre.org/techniques/T1070/004) to cleanup older artifacts.

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

## COLLECTION

### T1074 — Data Staged

**Taktik:** collection  
**MITRE Beschreibung (offiziell):**  
> Adversaries may stage collected data in a central location or directory prior to Exfiltration. Data may be kept in separate files or combined into one file through techniques such as [Archive Collected Data](https://attack.mitre.org/techniques/T1560). Interactive command shells may be used, and common functionality within [cmd](https://attack.mitre.org/software/S0106) and bash may be used to copy ...

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

### T1074.001 — Local Data Staging

**Taktik:** collection  
**MITRE Beschreibung (offiziell):**  
> Adversaries may stage collected data in a central location or directory on the local system prior to Exfiltration. Data may be kept in separate files or combined into one file through techniques such as [Archive Collected Data](https://attack.mitre.org/techniques/T1560). Interactive command shells may be used, and common functionality within [cmd](https://attack.mitre.org/software/S0106) and bash ...

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

### T1074.002 — Remote Data Staging

**Taktik:** collection  
**MITRE Beschreibung (offiziell):**  
> Adversaries may stage data collected from multiple systems in a central location or directory on one system prior to Exfiltration. Data may be kept in separate files or combined into one file through techniques such as [Archive Collected Data](https://attack.mitre.org/techniques/T1560). Interactive command shells may be used, and common functionality within [cmd](https://attack.mitre.org/software/...

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

## DEFENSE EVASION

### T1078.001 — Default Accounts

**Taktik:** defense-evasion, persistence, privilege-escalation, initial-access  
**MITRE Beschreibung (offiziell):**  
> Adversaries may obtain and abuse credentials of a default account as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion. Default accounts are those that are built-into an OS, such as the Guest or Administrator accounts on Windows systems. Default accounts also include default factory/provider set accounts on other types of systems, software, or devices, includ...

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

### T1078.002 — Domain Accounts

**Taktik:** defense-evasion, persistence, privilege-escalation, initial-access  
**MITRE Beschreibung (offiziell):**  
> Adversaries may obtain and abuse credentials of a domain account as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion.(Citation: TechNet Credential Theft) Domain accounts are those managed by Active Directory Domain Services where access and permissions are configured across systems and services that are part of that domain. Domain accounts can cover users, a...

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

### T1078.003 — Local Accounts

**Taktik:** defense-evasion, persistence, privilege-escalation, initial-access  
**MITRE Beschreibung (offiziell):**  
> Adversaries may obtain and abuse credentials of a local account as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion. Local accounts are those configured by an organization for use by users, remote support, services, or for administration on a single system or service.

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

## DISCOVERY

### T1087 — Account Discovery

**Taktik:** discovery  
**MITRE Beschreibung (offiziell):**  
> Adversaries may attempt to get a listing of valid accounts, usernames, or email addresses on a system or within a compromised environment. This information can help adversaries determine which accounts exist, which can aid in follow-on behavior such as brute-forcing, spear-phishing attacks, or account takeovers (e.g., [Valid Accounts](https://attack.mitre.org/techniques/T1078)).

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

### T1087.001 — Local Account

**Taktik:** discovery  
**MITRE Beschreibung (offiziell):**  
> Adversaries may attempt to get a listing of local system accounts. This information can help adversaries determine which local accounts exist on a system to aid in follow-on behavior.

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

### T1087.002 — Domain Account

**Taktik:** discovery  
**MITRE Beschreibung (offiziell):**  
> Adversaries may attempt to get a listing of domain accounts. This information can help adversaries determine which domain accounts exist to aid in follow-on behavior such as targeting specific accounts which possess particular privileges.

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

## COMMAND AND CONTROL

### T1090 — Proxy

**Taktik:** command-and-control  
**MITRE Beschreibung (offiziell):**  
> Adversaries may use a connection proxy to direct network traffic between systems or act as an intermediary for network communications to a command and control server to avoid direct connections to their infrastructure. Many tools exist that enable traffic redirection through proxies or port redirection, including [HTRAN](https://attack.mitre.org/software/S0040), ZXProxy, and ZXPortMap. (Citation: ...

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

### T1090.001 — Internal Proxy

**Taktik:** command-and-control  
**MITRE Beschreibung (offiziell):**  
> Adversaries may use an internal proxy to direct command and control traffic between two or more systems in a compromised environment. Many tools exist that enable traffic redirection through proxies or port redirection, including [HTRAN](https://attack.mitre.org/software/S0040), ZXProxy, and ZXPortMap. (Citation: Trend Micro APT Attack Tools) Adversaries use internal proxies to manage command and ...

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

### T1090.002 — External Proxy

**Taktik:** command-and-control  
**MITRE Beschreibung (offiziell):**  
> Adversaries may use an external proxy to act as an intermediary for network communications to a command and control server to avoid direct connections to their infrastructure. Many tools exist that enable traffic redirection through proxies or port redirection, including [HTRAN](https://attack.mitre.org/software/S0040), ZXProxy, and ZXPortMap. (Citation: Trend Micro APT Attack Tools) Adversaries u...

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

### T1090.003 — Multi-hop Proxy

**Taktik:** command-and-control  
**MITRE Beschreibung (offiziell):**  
> Adversaries may chain together multiple proxies to disguise the source of malicious traffic. Typically, a defender will be able to identify the last proxy traffic traversed before it enters their network; the defender may or may not be able to identify any previous proxies before the last-hop proxy. This technique makes identifying the original source of the malicious traffic even more difficult b...

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

### T1090.004 — Domain Fronting

**Taktik:** command-and-control  
**MITRE Beschreibung (offiziell):**  
> Adversaries may take advantage of routing schemes in Content Delivery Networks (CDNs) and other services which host multiple domains to obfuscate the intended destination of HTTPS traffic or traffic tunneled through HTTPS. (Citation: Fifield Blocking Resistent Communication through domain fronting 2015) Domain fronting involves using different domain names in the SNI field of the TLS header and th...

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

## PERSISTENCE

### T1098.004 — SSH Authorized Keys

**Taktik:** persistence, privilege-escalation  
**MITRE Beschreibung (offiziell):**  
> Adversaries may modify the SSH <code>authorized_keys</code> file to maintain persistence on a victim host. Linux distributions, macOS, and ESXi hypervisors commonly use key-based authentication to secure the authentication process of SSH sessions for remote management. The <code>authorized_keys</code> file in SSH specifies the SSH keys that can be used for logging into the user account for which t...

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

### T1098.007 — Additional Local or Domain Groups

**Taktik:** persistence, privilege-escalation  
**MITRE Beschreibung (offiziell):**  
> An adversary may add additional local or domain groups to an adversary-controlled account to maintain persistent access to a system or domain.

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

## CREDENTIAL ACCESS

### T1110.002 — Password Cracking

**Taktik:** credential-access  
**MITRE Beschreibung (offiziell):**  
> Adversaries may use password cracking to attempt to recover usable credentials, such as plaintext passwords, when credential material such as password hashes are obtained. [OS Credential Dumping](https://attack.mitre.org/techniques/T1003) can be used to obtain password hashes, this may only get an adversary so far when [Pass the Hash](https://attack.mitre.org/techniques/T1550/002) is not an option...

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

### T1110.003 — Password Spraying

**Taktik:** credential-access  
**MITRE Beschreibung (offiziell):**  
> Adversaries may use a single or small list of commonly used passwords against many different accounts to attempt to acquire valid account credentials. Password spraying uses one password (e.g. 'Password01'), or a small list of commonly used passwords, that may match the complexity policy of the domain. Logins are attempted with that password against many different accounts on a network to avoid ac...

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

### T1110.004 — Credential Stuffing

**Taktik:** credential-access  
**MITRE Beschreibung (offiziell):**  
> Adversaries may use credentials obtained from breach dumps of unrelated accounts to gain access to target accounts through credential overlap. Occasionally, large numbers of username and password pairs are dumped online when a website or service is compromised and the user account credentials accessed. The information may be useful to an adversary attempting to compromise accounts by taking advant...

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

## COLLECTION

### T1113 — Screen Capture

**Taktik:** collection  
**MITRE Beschreibung (offiziell):**  
> Adversaries may attempt to take screen captures of the desktop to gather information over the course of an operation. Screen capturing functionality may be included as a feature of a remote access tool used in post-compromise operations. Taking a screenshot is also typically possible through native utilities or API calls, such as <code>CopyFromScreen</code>, <code>xwd</code>, or <code>screencaptur...

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

### T1114 — Email Collection

**Taktik:** collection  
**MITRE Beschreibung (offiziell):**  
> Adversaries may target user email to collect sensitive information. Emails may contain sensitive data, including trade secrets or personal information, that can prove valuable to adversaries. Emails may also contain details of ongoing incident response operations, which may allow adversaries to adjust their techniques in order to maintain persistence or evade defenses.(Citation: TrustedSec OOB Com...

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

### T1114.003 — Email Forwarding Rule

**Taktik:** collection  
**MITRE Beschreibung (offiziell):**  
> Adversaries may setup email forwarding rules to collect sensitive information. Adversaries may abuse email forwarding rules to monitor the activities of a victim, steal information, and further gain intelligence on the victim or the victim’s organization to use as part of further exploits or operations.(Citation: US-CERT TA18-068A 2018) Furthermore, email forwarding rules can allow adversaries to ...

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

## PERSISTENCE

### T1133 — External Remote Services

**Taktik:** persistence, initial-access  
**MITRE Beschreibung (offiziell):**  
> Adversaries may leverage external-facing remote services to initially access and/or persist within a network. Remote services such as VPNs, Citrix, and other access mechanisms allow users to connect to internal enterprise network resources from external locations. There are often remote service gateways that manage connections and credential authentication for these services. Services such as [Win...

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

## DISCOVERY

### T1135 — Network Share Discovery

**Taktik:** discovery  
**MITRE Beschreibung (offiziell):**  
> Adversaries may look for folders and drives shared on remote systems as a means of identifying sources of information to gather as a precursor for Collection and to identify potential systems of interest for Lateral Movement. Networks often contain shared network drives and folders that enable users to access file directories on various systems across a network.

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

## PERSISTENCE

### T1136 — Create Account

**Taktik:** persistence  
**MITRE Beschreibung (offiziell):**  
> Adversaries may create an account to maintain access to victim systems.(Citation: Symantec WastedLocker June 2020) With a sufficient level of access, creating such accounts may be used to establish secondary credentialed access that do not require persistent remote access tools to be deployed on the system.

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

### T1136.001 — Local Account

**Taktik:** persistence  
**MITRE Beschreibung (offiziell):**  
> Adversaries may create a local account to maintain access to victim systems. Local accounts are those configured by an organization for use by users, remote support, services, or for administration on a single system or service.

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

### T1136.002 — Domain Account

**Taktik:** persistence  
**MITRE Beschreibung (offiziell):**  
> Adversaries may create a domain account to maintain access to victim systems. Domain accounts are those managed by Active Directory Domain Services where access and permissions are configured across systems and services that are part of that domain. Domain accounts can cover user, administrator, and service accounts. With a sufficient level of access, the <code>net user /add /domain</code> command...

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

## DISCOVERY

### T1201 — Password Policy Discovery

**Taktik:** discovery  
**MITRE Beschreibung (offiziell):**  
> Adversaries may attempt to access detailed information about the password policy used within an enterprise network or cloud environment. Password policies are a way to enforce complex passwords that are difficult to guess or crack through [Brute Force](https://attack.mitre.org/techniques/T1110). This information may help the adversary to create a list of common passwords and launch dictionary and/...

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

## COMMAND AND CONTROL

### T1219 — Remote Access Tools

**Taktik:** command-and-control  
**MITRE Beschreibung (offiziell):**  
> An adversary may use legitimate remote access tools to establish an interactive command and control channel within a network. Remote access tools create a session between two trusted hosts through a graphical interface, a command line interaction, a protocol tunnel via development or management software, or hardware-level access such as KVM (Keyboard, Video, Mouse) over IP solutions. Desktop suppo...

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

### T1219.001 — IDE Tunneling

**Taktik:** command-and-control  
**MITRE Beschreibung (offiziell):**  
> Adversaries may abuse Integrated Development Environment (IDE) software with remote development features to establish an interactive command and control channel on target systems within a network. IDE tunneling combines SSH, port forwarding, file sharing, and debugging into a single secure connection, letting developers work on remote systems as if they were local. Unlike SSH and port forwarding, ...

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

### T1219.002 — Remote Desktop Software

**Taktik:** command-and-control  
**MITRE Beschreibung (offiziell):**  
> An adversary may use legitimate desktop support software to establish an interactive command and control channel to target systems within networks. Desktop support software provides a graphical interface for remotely controlling another computer, transmitting the display output, keyboard input, and mouse control between devices using various protocols. Desktop support software, such as `VNC`, `Tea...

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

### T1219.003 — Remote Access Hardware

**Taktik:** command-and-control  
**MITRE Beschreibung (offiziell):**  
> An adversary may use legitimate remote access hardware to establish an interactive command and control channel to target systems within networks. These services, including IP-based keyboard, video, or mouse (KVM) devices such as TinyPilot and PiKVM, are commonly used as legitimate tools and may be allowed by peripheral device policies within a target environment.

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

## DEFENSE EVASION

### T1222 — File and Directory Permissions Modification

**Taktik:** defense-evasion  
**MITRE Beschreibung (offiziell):**  
> Adversaries may modify file or directory permissions/attributes to evade access control lists (ACLs) and access protected files.(Citation: Hybrid Analysis Icacls1 June 2018)(Citation: Hybrid Analysis Icacls2 May 2018) File and directory permissions are commonly managed by ACLs configured by the file or directory owner, or users with the appropriate permissions. File and directory ACL implementatio...

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

### T1222.002 — Linux and Mac File and Directory Permissions Modification

**Taktik:** defense-evasion  
**MITRE Beschreibung (offiziell):**  
> Adversaries may modify file or directory permissions/attributes to evade access control lists (ACLs) and access protected files.(Citation: Hybrid Analysis Icacls1 June 2018)(Citation: Hybrid Analysis Icacls2 May 2018) File and directory permissions are commonly managed by ACLs configured by the file or directory owner, or users with the appropriate permissions. File and directory ACL implementatio...

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

## IMPACT

### T1486 — Data Encrypted for Impact

**Taktik:** impact  
**MITRE Beschreibung (offiziell):**  
> Adversaries may encrypt data on target systems or on large numbers of systems in a network to interrupt availability to system and network resources. They can attempt to render stored data inaccessible by encrypting files or data on local and remote drives and withholding access to a decryption key. This may be done in order to extract monetary compensation from a victim in exchange for decryption...

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

### T1489 — Service Stop

**Taktik:** impact  
**MITRE Beschreibung (offiziell):**  
> Adversaries may stop or disable services on a system to render those services unavailable to legitimate users. Stopping critical services or processes can inhibit or stop response to an incident or aid in the adversary's overall objectives to cause damage to the environment.(Citation: Talos Olympic Destroyer 2018)(Citation: Novetta Blockbuster)

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

### T1490 — Inhibit System Recovery

**Taktik:** impact  
**MITRE Beschreibung (offiziell):**  
> Adversaries may delete or remove built-in data and turn off services designed to aid in the recovery of a corrupted system to prevent recovery.(Citation: Talos Olympic Destroyer 2018)(Citation: FireEye WannaCry 2017) This may deny access to available backups and recovery options.

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

### T1496 — Resource Hijacking

**Taktik:** impact  
**MITRE Beschreibung (offiziell):**  
> Adversaries may leverage the resources of co-opted systems to complete resource-intensive tasks, which may impact system and/or hosted service availability.

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

### T1496.001 — Compute Hijacking

**Taktik:** impact  
**MITRE Beschreibung (offiziell):**  
> Adversaries may leverage the compute resources of co-opted systems to complete resource-intensive tasks, which may impact system and/or hosted service availability.

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

### T1496.002 — Bandwidth Hijacking

**Taktik:** impact  
**MITRE Beschreibung (offiziell):**  
> Adversaries may leverage the network bandwidth resources of co-opted systems to complete resource-intensive tasks, which may impact system and/or hosted service availability.

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

## PERSISTENCE

### T1505 — Server Software Component

**Taktik:** persistence  
**MITRE Beschreibung (offiziell):**  
> Adversaries may abuse legitimate extensible development features of servers to establish persistent access to systems. Enterprise server applications may include features that allow developers to write and install software or scripts to extend the functionality of the main application. Adversaries may install malicious components to extend and abuse server applications.(Citation: volexity_0day_sop...

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

### T1505.001 — SQL Stored Procedures

**Taktik:** persistence  
**MITRE Beschreibung (offiziell):**  
> Adversaries may abuse SQL stored procedures to establish persistent access to systems. SQL Stored Procedures are code that can be saved and reused so that database users do not waste time rewriting frequently used SQL queries. Stored procedures can be invoked via SQL statements to the database using the procedure name or via defined events (e.g. when a SQL server application is started/restarted).

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

### T1505.002 — Transport Agent

**Taktik:** persistence  
**MITRE Beschreibung (offiziell):**  
> Adversaries may abuse Microsoft transport agents to establish persistent access to systems. Microsoft Exchange transport agents can operate on email messages passing through the transport pipeline to perform various tasks such as filtering spam, filtering malicious attachments, journaling, or adding a corporate signature to the end of all outgoing emails.(Citation: Microsoft TransportAgent Jun 201...

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

## DISCOVERY

### T1518 — Software Discovery

**Taktik:** discovery  
**MITRE Beschreibung (offiziell):**  
> Adversaries may attempt to get a listing of software and software versions that are installed on a system or in a cloud environment. Adversaries may use the information from [Software Discovery](https://attack.mitre.org/techniques/T1518) during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

### T1518.001 — Security Software Discovery

**Taktik:** discovery  
**MITRE Beschreibung (offiziell):**  
> Adversaries may attempt to get a listing of security software, configurations, defensive tools, and sensors that are installed on a system or in a cloud environment. This may include things such as cloud monitoring agents and anti-virus. Adversaries may use the information from [Security Software Discovery](https://attack.mitre.org/techniques/T1518/001) during automated discovery to shape follow-o...

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

### T1518.002 — Backup Software Discovery

**Taktik:** discovery  
**MITRE Beschreibung (offiziell):**  
> Adversaries may attempt to get a listing of backup software or configurations that are installed on a system. Adversaries may use this information to shape follow-on behaviors, such as [Data Destruction](https://attack.mitre.org/techniques/T1485), [Inhibit System Recovery](https://attack.mitre.org/techniques/T1490), or [Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486).

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

## IMPACT

### T1529 — System Shutdown/Reboot

**Taktik:** impact  
**MITRE Beschreibung (offiziell):**  
> Adversaries may shutdown/reboot systems to interrupt access to, or aid in the destruction of, those systems. Operating systems may contain commands to initiate a shutdown/reboot of a machine or network device. In some cases, these commands may also be used to initiate a shutdown/reboot of a remote computer or network device via [Network Device CLI](https://attack.mitre.org/techniques/T1059/008) (e...

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

## PERSISTENCE

### T1543 — Create or Modify System Process

**Taktik:** persistence, privilege-escalation  
**MITRE Beschreibung (offiziell):**  
> Adversaries may create or modify system-level processes to repeatedly execute malicious payloads as part of persistence. When operating systems boot up, they can start processes that perform background system functions. On Windows and Linux, these system processes are referred to as services.(Citation: TechNet Services) On macOS, launchd processes known as [Launch Daemon](https://attack.mitre.org/...

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

## PRIVILEGE ESCALATION

### T1546 — Event Triggered Execution

**Taktik:** privilege-escalation, persistence  
**MITRE Beschreibung (offiziell):**  
> Adversaries may establish persistence and/or elevate privileges using system mechanisms that trigger execution based on specific events. Various operating systems have means to monitor and subscribe to events such as logons or other user activity such as running specific applications/binaries. Cloud environments may also support various functions and services that monitor and can be invoked in res...

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

### T1546.004 — Unix Shell Configuration Modification

**Taktik:** privilege-escalation, persistence  
**MITRE Beschreibung (offiziell):**  
> Adversaries may establish persistence through executing malicious commands triggered by a user’s shell. User [Unix Shell](https://attack.mitre.org/techniques/T1059/004)s execute several configuration scripts at different points throughout the session based on events. For example, when a user opens a command-line interface or remotely logs in (such as via SSH) a login shell is initiated. The login ...

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

### T1546.005 — Trap

**Taktik:** privilege-escalation, persistence  
**MITRE Beschreibung (offiziell):**  
> Adversaries may establish persistence by executing malicious content triggered by an interrupt signal. The <code>trap</code> command allows programs and shells to specify commands that will be executed upon receiving interrupt signals. A common situation is a script allowing for graceful termination and handling of common keyboard interrupts like <code>ctrl+c</code> and <code>ctrl+d</code>.

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

### T1546.016 — Installer Packages

**Taktik:** privilege-escalation, persistence  
**MITRE Beschreibung (offiziell):**  
> Adversaries may establish persistence and elevate privileges by using an installer to trigger the execution of malicious content. Installer packages are OS specific and contain the resources an operating system needs to install applications on a system. Installer packages can include scripts that run prior to installation as well as after installation is complete. Installer scripts may inherit ele...

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

## PERSISTENCE

### T1546.017 — Udev Rules

**Taktik:** persistence, privilege-escalation  
**MITRE Beschreibung (offiziell):**  
> Adversaries may maintain persistence through executing malicious content triggered using udev rules. Udev is the Linux kernel device manager that dynamically manages device nodes, handles access to pseudo-device files in the `/dev` directory, and responds to hardware events, such as when external devices like hard drives or keyboards are plugged in or removed. Udev uses rule files with `match keys...

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

### T1546.018 — Python Startup Hooks

**Taktik:** persistence, privilege-escalation  
**MITRE Beschreibung (offiziell):**  
> Adversaries may achieve persistence by leveraging Python’s startup mechanisms, including path configuration (`.pth`) files and the `sitecustomize.py` or `usercustomize.py` modules. These files are automatically processed during the initialization of the Python interpreter, allowing for the execution of arbitrary code whenever Python is invoked.(Citation: Volexity GlobalProtect CVE 2024)

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

### T1547 — Boot or Logon Autostart Execution

**Taktik:** persistence, privilege-escalation  
**MITRE Beschreibung (offiziell):**  
> Adversaries may configure system settings to automatically execute a program during system boot or logon to maintain persistence or gain higher-level privileges on compromised systems. Operating systems may have mechanisms for automatically running a program on system boot or account logon.(Citation: Microsoft Run Key)(Citation: MSDN Authentication Packages)(Citation: Microsoft TimeProvider)(Citat...

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

### T1547.006 — Kernel Modules and Extensions

**Taktik:** persistence, privilege-escalation  
**MITRE Beschreibung (offiziell):**  
> Adversaries may modify the kernel to automatically execute programs on system boot. Loadable Kernel Modules (LKMs) are pieces of code that can be loaded and unloaded into the kernel upon demand. They extend the functionality of the kernel without the need to reboot the system. For example, one type of module is the device driver, which allows the kernel to access hardware connected to the system.(...

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

### T1547.013 — XDG Autostart Entries

**Taktik:** persistence, privilege-escalation  
**MITRE Beschreibung (offiziell):**  
> Adversaries may add or modify XDG Autostart Entries to execute malicious programs or commands when a user’s desktop environment is loaded at login. XDG Autostart entries are available for any XDG-compliant Linux system. XDG Autostart entries use Desktop Entry files (`.desktop`) to configure the user’s desktop environment upon user login. These configuration files determine what applications launch...

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

## PRIVILEGE ESCALATION

### T1548 — Abuse Elevation Control Mechanism

**Taktik:** privilege-escalation, defense-evasion  
**MITRE Beschreibung (offiziell):**  
> Adversaries may circumvent mechanisms designed to control elevate privileges to gain higher-level permissions. Most modern systems contain native elevation control mechanisms that are intended to limit privileges that a user can perform on a machine. Authorization has to be granted to specific users in order to perform tasks that can be considered of higher risk.(Citation: TechNet How UAC Works)(C...

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

### T1548.001 — Setuid and Setgid

**Taktik:** privilege-escalation, defense-evasion  
**MITRE Beschreibung (offiziell):**  
> An adversary may abuse configurations where an application has the setuid or setgid bits set in order to get code running in a different (and possibly more privileged) user’s context. On Linux or macOS, when the setuid or setgid bits are set for an application binary, the application will run with the privileges of the owning user or group respectively.(Citation: setuid man page) Normally an appli...

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

### T1548.003 — Sudo and Sudo Caching

**Taktik:** privilege-escalation, defense-evasion  
**MITRE Beschreibung (offiziell):**  
> Adversaries may perform sudo caching and/or use the sudoers file to elevate privileges. Adversaries may do this to execute commands as other users or spawn processes with higher privileges.

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

## CREDENTIAL ACCESS

### T1552 — Unsecured Credentials

**Taktik:** credential-access  
**MITRE Beschreibung (offiziell):**  
> Adversaries may search compromised systems to find and obtain insecurely stored credentials. These credentials can be stored and/or misplaced in many locations on a system, including plaintext files (e.g. [Shell History](https://attack.mitre.org/techniques/T1552/003)), operating system or application-specific repositories (e.g. [Credentials in Registry](https://attack.mitre.org/techniques/T1552/00...

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

### T1552.001 — Credentials In Files

**Taktik:** credential-access  
**MITRE Beschreibung (offiziell):**  
> Adversaries may search local file systems and remote file shares for files containing insecurely stored credentials. These can be files created by users to store their own credentials, shared credential stores for a group of individuals, configuration files containing passwords for a system or service, or source code/binary files containing embedded passwords.

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

### T1552.003 — Shell History

**Taktik:** credential-access  
**MITRE Beschreibung (offiziell):**  
> Adversaries may search the command history on compromised systems for insecurely stored credentials.

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

### T1552.004 — Private Keys

**Taktik:** credential-access  
**MITRE Beschreibung (offiziell):**  
> Adversaries may search for private key certificate files on compromised systems for insecurely stored credentials. Private cryptographic keys and certificates are used for authentication, encryption/decryption, and digital signatures.(Citation: Wikipedia Public Key Crypto) Common key and certificate file extensions include: .key, .pgp, .gpg, .ppk., .p12, .pem, .pfx, .cer, .p7b, .asc.

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

### T1555 — Credentials from Password Stores

**Taktik:** credential-access  
**MITRE Beschreibung (offiziell):**  
> Adversaries may search for common password storage locations to obtain user credentials.(Citation: F-Secure The Dukes) Passwords are stored in several places on a system, depending on the operating system or application holding the credentials. There are also specific applications and services that store passwords to make them easier for users to manage and maintain, such as password managers and ...

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

### T1555.002 — Securityd Memory

**Taktik:** credential-access  
**MITRE Beschreibung (offiziell):**  
> An adversary with root access may gather credentials by reading `securityd`’s memory. `securityd` is a service/daemon responsible for implementing security protocols such as encryption and authorization.(Citation: Apple Dev SecurityD) A privileged adversary may be able to scan through `securityd`'s memory to find the correct sequence of keys to decrypt the user’s logon keychain. This may provide t...

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

### T1555.003 — Credentials from Web Browsers

**Taktik:** credential-access  
**MITRE Beschreibung (offiziell):**  
> Adversaries may acquire credentials from web browsers by reading files specific to the target browser.(Citation: Talos Olympic Destroyer 2018) Web browsers commonly save credentials such as website usernames and passwords so that they do not need to be entered manually in the future. Web browsers typically store the credentials in an encrypted format within a credential store; however, methods exi...

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

### T1555.005 — Password Managers

**Taktik:** credential-access  
**MITRE Beschreibung (offiziell):**  
> Adversaries may acquire user credentials from third-party password managers.(Citation: ise Password Manager February 2019) Password managers are applications designed to store user credentials, normally in an encrypted database. Credentials are typically accessible after a user provides a master password that unlocks the database. After the database is unlocked, these credentials may be copied to ...

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

### T1556 — Modify Authentication Process

**Taktik:** credential-access, defense-evasion, persistence  
**MITRE Beschreibung (offiziell):**  
> Adversaries may modify authentication mechanisms and processes to access user credentials or enable otherwise unwarranted access to accounts. The authentication process is handled by mechanisms, such as the Local Security Authentication Server (LSASS) process and the Security Accounts Manager (SAM) on Windows, pluggable authentication modules (PAM) on Unix-based systems, and authorization plugins ...

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

### T1556.003 — Pluggable Authentication Modules

**Taktik:** credential-access, defense-evasion, persistence  
**MITRE Beschreibung (offiziell):**  
> Adversaries may modify pluggable authentication modules (PAM) to access user credentials or enable otherwise unwarranted access to accounts. PAM is a modular system of configuration files, libraries, and executable files which guide authentication for many services. The most common authentication module is <code>pam_unix.so</code>, which retrieves, sets, and verifies account authentication informa...

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

### T1556.006 — Multi-Factor Authentication

**Taktik:** credential-access, defense-evasion, persistence  
**MITRE Beschreibung (offiziell):**  
> Adversaries may disable or modify multi-factor authentication (MFA) mechanisms to enable persistent access to compromised accounts.

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

## COLLECTION

### T1560 — Archive Collected Data

**Taktik:** collection  
**MITRE Beschreibung (offiziell):**  
> An adversary may compress and/or encrypt data that is collected prior to exfiltration. Compressing the data can help to obfuscate the collected data and minimize the amount of data sent over the network.(Citation: DOJ GRU Indictment Jul 2018) Encryption can be used to hide information that is being exfiltrated from detection or make exfiltration less conspicuous upon inspection by a defender.

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

### T1560.001 — Archive via Utility

**Taktik:** collection  
**MITRE Beschreibung (offiziell):**  
> Adversaries may use utilities to compress and/or encrypt collected data prior to exfiltration. Many utilities include functionalities to compress, encrypt, or otherwise package data into a format that is easier/more secure to transport.

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

### T1560.002 — Archive via Library

**Taktik:** collection  
**MITRE Beschreibung (offiziell):**  
> An adversary may compress or encrypt data that is collected prior to exfiltration using 3rd party libraries. Many libraries exist that can archive data, including [Python](https://attack.mitre.org/techniques/T1059/006) rarfile (Citation: PyPI RAR), libzip (Citation: libzip), and zlib (Citation: Zlib Github). Most libraries include functionality to encrypt and/or compress data.

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

### T1560.003 — Archive via Custom Method

**Taktik:** collection  
**MITRE Beschreibung (offiziell):**  
> An adversary may compress or encrypt data that is collected prior to exfiltration using a custom method. Adversaries may choose to use custom archival methods, such as encryption with XOR or stream ciphers implemented with no external library or utility references. Custom implementations of well-known compression algorithms have also been used.(Citation: ESET Sednit Part 2)

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

## LATERAL MOVEMENT

### T1563 — Remote Service Session Hijacking

**Taktik:** lateral-movement  
**MITRE Beschreibung (offiziell):**  
> Adversaries may take control of preexisting sessions with remote services to move laterally in an environment. Users may use valid credentials to log into a service specifically designed to accept remote connections, such as telnet, SSH, and RDP. When a user logs into a service, a session will be established that will allow them to maintain a continuous interaction with that service.

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

### T1563.001 — SSH Hijacking

**Taktik:** lateral-movement  
**MITRE Beschreibung (offiziell):**  
> Adversaries may hijack a legitimate user's SSH session to move laterally within an environment. Secure Shell (SSH) is a standard means of remote access on Linux and macOS systems. It allows a user to connect to another system via an encrypted tunnel, commonly authenticating through a password, certificate or the use of an asymmetric encryption key pair.

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

## DEFENSE EVASION

### T1564 — Hide Artifacts

**Taktik:** defense-evasion  
**MITRE Beschreibung (offiziell):**  
> Adversaries may attempt to hide artifacts associated with their behaviors to evade detection. Operating systems may have features to hide various artifacts, such as important system files and administrative task execution, to avoid disrupting user work environments and prevent users from changing files or features on the system. Adversaries may abuse these features to hide artifacts such as files,...

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

### T1564.001 — Hidden Files and Directories

**Taktik:** defense-evasion  
**MITRE Beschreibung (offiziell):**  
> Adversaries may set files and directories to be hidden to evade detection mechanisms. To prevent normal users from accidentally changing special files on a system, most operating systems have the concept of a ‘hidden’ file. These files don’t show up when a user browses the file system with a GUI or when using normal commands on the command line. Users must explicitly ask to show the hidden files e...

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

### T1564.002 — Hidden Users

**Taktik:** defense-evasion  
**MITRE Beschreibung (offiziell):**  
> Adversaries may use hidden users to hide the presence of user accounts they create or modify. Administrators may want to hide users when there are many user accounts on a given system or if they want to hide their administrative or other management accounts from other users.

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

### T1564.003 — Hidden Window

**Taktik:** defense-evasion  
**MITRE Beschreibung (offiziell):**  
> Adversaries may use hidden windows to conceal malicious activity from the plain sight of users. In some cases, windows that would typically be displayed when an application carries out an operation can be hidden. This may be utilized by system administrators to avoid disrupting user work environments when carrying out administrative tasks.

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

### T1564.005 — Hidden File System

**Taktik:** defense-evasion  
**MITRE Beschreibung (offiziell):**  
> Adversaries may use a hidden file system to conceal malicious activity from users and security tools. File systems provide a structure to store and access data from physical storage. Typically, a user engages with a file system through applications that allow them to access files and directories, which are an abstraction from their physical location (ex: disk sector). Standard file systems include...

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

### T1564.006 — Run Virtual Instance

**Taktik:** defense-evasion  
**MITRE Beschreibung (offiziell):**  
> Adversaries may carry out malicious operations using a virtual instance to avoid detection. A wide variety of virtualization technologies exist that allow for the emulation of a computer or computing environment. By running malicious code inside of a virtual instance, adversaries can hide artifacts associated with their behavior from security tools that are unable to monitor activity inside the vi...

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

### T1564.007 — VBA Stomping

**Taktik:** defense-evasion  
**MITRE Beschreibung (offiziell):**  
> Adversaries may hide malicious Visual Basic for Applications (VBA) payloads embedded within MS Office documents by replacing the VBA source code with benign data.(Citation: FireEye VBA stomp Feb 2020)

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

### T1564.008 — Email Hiding Rules

**Taktik:** defense-evasion  
**MITRE Beschreibung (offiziell):**  
> Adversaries may use email rules to hide inbound emails in a compromised user's mailbox. Many email clients allow users to create inbox rules for various email functions, including moving emails to other folders, marking emails as read, or deleting emails. Rules may be created or modified within email clients or through external features such as the <code>New-InboxRule</code> or <code>Set-InboxRule...

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

### T1564.011 — Ignore Process Interrupts

**Taktik:** defense-evasion  
**MITRE Beschreibung (offiziell):**  
> Adversaries may evade defensive mechanisms by executing commands that hide from process interrupt signals. Many operating systems use signals to deliver messages to control process behavior. Command interpreters often include specific commands/flags that ignore errors and other hangups, such as when the user of the active session logs off.(Citation: Linux Signal Man)  These interrupt signals may a...

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

### T1564.012 — File/Path Exclusions

**Taktik:** defense-evasion  
**MITRE Beschreibung (offiziell):**  
> Adversaries may attempt to hide their file-based artifacts by writing them to specific folders or file names excluded from antivirus (AV) scanning and other defensive capabilities. AV and other file-based scanners often include exclusions to optimize performance as well as ease installation and legitimate use of applications. These exclusions may be contextual (e.g., scans are only initiated in re...

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

### T1564.013 — Bind Mounts

**Taktik:** defense-evasion  
**MITRE Beschreibung (offiziell):**  
> Adversaries may abuse bind mounts on file structures to hide their activity and artifacts from native utilities. A bind mount maps a directory or file from one location on the filesystem to another, similar to a shortcut on Windows. It’s commonly used to provide access to specific files or directories across different environments, such as inside containers or chroot environments, and requires sud...

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

### T1564.014 — Extended Attributes

**Taktik:** defense-evasion  
**MITRE Beschreibung (offiziell):**  
> Adversaries may abuse extended attributes (xattrs) on macOS and Linux to hide their malicious data in order to evade detection. Extended attributes are key-value pairs of file and directory metadata used by both macOS and Linux. They are not visible through standard tools like `Finder`,  `ls`, or `cat` and require utilities such as `xattr` (macOS) or `getfattr` (Linux) for inspection. Operating sy...

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

## EXECUTION

### T1569 — System Services

**Taktik:** execution  
**MITRE Beschreibung (offiziell):**  
> Adversaries may abuse system services or daemons to execute commands or programs. Adversaries can execute malicious content by interacting with or creating services either locally or remotely. Many services are set to run at boot, which can aid in achieving persistence ([Create or Modify System Process](https://attack.mitre.org/techniques/T1543)), but adversaries can also abuse services for one-ti...

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

### T1569.003 — Systemctl

**Taktik:** execution  
**MITRE Beschreibung (offiziell):**  
> Adversaries may abuse systemctl to execute commands or programs. Systemctl is the primary interface for systemd, the Linux init system and service manager. Typically invoked from a shell, Systemctl can also be integrated into scripts or applications.

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

## LATERAL MOVEMENT

### T1570 — Lateral Tool Transfer

**Taktik:** lateral-movement  
**MITRE Beschreibung (offiziell):**  
> Adversaries may transfer tools or other files between systems in a compromised environment. Once brought into the victim environment (i.e., [Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105)) files may then be copied from one system to another to stage adversary tools or other files over the course of an operation.

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

## COMMAND AND CONTROL

### T1571 — Non-Standard Port

**Taktik:** command-and-control  
**MITRE Beschreibung (offiziell):**  
> Adversaries may communicate using a protocol and port pairing that are typically not associated. For example, HTTPS over port 8088(Citation: Symantec Elfin Mar 2019) or port 587(Citation: Fortinet Agent Tesla April 2018) as opposed to the traditional port 443. Adversaries may make changes to the standard port used by a protocol to bypass filtering or muddle analysis/parsing of network data.

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

### T1572 — Protocol Tunneling

**Taktik:** command-and-control  
**MITRE Beschreibung (offiziell):**  
> Adversaries may tunnel network communications to and from a victim system within a separate protocol to avoid detection/network filtering and/or enable access to otherwise unreachable systems. Tunneling involves explicitly encapsulating a protocol within another. This behavior may conceal malicious traffic by blending in with existing traffic and/or provide an outer layer of encryption (similar to...

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

## PERSISTENCE

### T1574 — Hijack Execution Flow

**Taktik:** persistence, privilege-escalation, defense-evasion  
**MITRE Beschreibung (offiziell):**  
> Adversaries may execute their own malicious payloads by hijacking the way operating systems run programs. Hijacking execution flow can be for the purposes of persistence, since this hijacked execution may reoccur over time. Adversaries may also use these mechanisms to elevate privileges or evade defenses, such as application control or other restrictions on execution.

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

### T1574.006 — Dynamic Linker Hijacking

**Taktik:** persistence, privilege-escalation, defense-evasion  
**MITRE Beschreibung (offiziell):**  
> Adversaries may execute their own malicious payloads by hijacking environment variables the dynamic linker uses to load shared libraries. During the execution preparation phase of a program, the dynamic linker loads specified absolute paths of shared libraries from various environment variables and files, such as <code>LD_PRELOAD</code> on Linux or <code>DYLD_INSERT_LIBRARIES</code> on macOS.(Cita...

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

### T1574.007 — Path Interception by PATH Environment Variable

**Taktik:** persistence, privilege-escalation, defense-evasion  
**MITRE Beschreibung (offiziell):**  
> Adversaries may execute their own malicious payloads by hijacking environment variables used to load libraries. The PATH environment variable contains a list of directories (User and System) that the OS searches sequentially through in search of the binary that was called from a script or the command line.

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---

## DISCOVERY

### T1654 — Log Enumeration

**Taktik:** discovery  
**MITRE Beschreibung (offiziell):**  
> Adversaries may enumerate system and service logs to find useful data. These logs may highlight various types of valuable insights for an adversary, such as user authentication records ([Account Discovery](https://attack.mitre.org/techniques/T1087)), security or vulnerable software ([Software Discovery](https://attack.mitre.org/techniques/T1518)), or hosts within a compromised network ([Remote Sys...

**Keywords (manuell eintragen):**
```
# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'
```

**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen

---
