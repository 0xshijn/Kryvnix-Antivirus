; Kryvnix Antivirus v2.0.0 — Inno Setup Windows Installer Script
; Build with Inno Setup 6 (iscc installer\KryvnixAntivirus.iss)

#define MyAppName "Kryvnix Antivirus"
#define MyAppVersion "2.0.0"
#define MyAppPublisher "Kryvnix Security"
#define MyAppURL "https://github.com/0xshijn/Kryvnix-Antivirus"
#define MyAppExeName "KryvnixAntivirus.exe"

[Setup]
AppId={{7E8E6E74-9F42-4B55-9D5E-1A2B3C4D5E6F}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
OutputDir=output
OutputBaseFilename=KryvnixAntivirus-Setup-v{#MyAppVersion}-win-x64
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequiredOverridesAllowed=dialog

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a Desktop shortcut"; GroupDescription: "Additional icons:"
Name: "contextmenu"; Description: "Add 'Scan with Kryvnix Antivirus' to Windows Explorer right-click menu"; GroupDescription: "Windows Integration:"

[Files]
Source: "..\..\Demo\Release-win-x64\KryvnixAntivirus.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\engine\bin\kryvnix_engine.exe"; DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Registry]
Root: HKCU; Subkey: "Software\Classes\*\shell\KryvnixAntivirusScan"; ValueType: string; ValueName: ""; ValueData: "Quét bằng Kryvnix Antivirus"; Flags: uninsdeletekey; Tasks: contextmenu
Root: HKCU; Subkey: "Software\Classes\*\shell\KryvnixAntivirusScan\command"; ValueType: string; ValueName: ""; ValueData: """{app}\{#MyAppExeName}"" --scan ""%1"""; Flags: uninsdeletekey; Tasks: contextmenu
Root: HKCU; Subkey: "Software\Classes\Directory\shell\KryvnixAntivirusScan"; ValueType: string; ValueName: ""; ValueData: "Quét bằng Kryvnix Antivirus"; Flags: uninsdeletekey; Tasks: contextmenu
Root: HKCU; Subkey: "Software\Classes\Directory\shell\KryvnixAntivirusScan\command"; ValueType: string; ValueName: ""; ValueData: """{app}\{#MyAppExeName}"" --scan ""%1"""; Flags: uninsdeletekey; Tasks: contextmenu

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "Launch {#MyAppName}"; Flags: nowait postinstall skipifsilent
