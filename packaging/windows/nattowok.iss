; Windows installer for NattoWok Limiter (Inno Setup 6).
; Built by CI: iscc /DAppVersion=x.y.z packaging\windows\nattowok.iss
; Installs nwld (as the "NattoWokLimiter" service, started now and with
; Windows), the nwl CLI and the nattowok desktop app, with Start menu entries.

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif

[Setup]
AppId={{6F0B0D1E-7C2B-4E58-9A4C-4E5741544F4B}
AppName=NattoWok Limiter
AppVersion={#AppVersion}
AppPublisher=The NattoWokLimiter contributors
AppPublisherURL=https://github.com/nasi-lemak/NattoWokLimiter
DefaultDirName={autopf}\NattoWok Limiter
DefaultGroupName=NattoWok Limiter
DisableProgramGroupPage=yes
LicenseFile=..\..\LICENSE
OutputDir=..\..\target\installer
OutputBaseFilename=nattowok-setup-x86_64
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=admin
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
UninstallDisplayIcon={app}\nattowok.exe
; The service holds nwld.exe open; it is stopped before files are replaced.
CloseApplications=yes

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; Flags: unchecked
Name: "autostart"; Description: "Start the app with Windows, in the tray"; Flags: unchecked

[Files]
Source: "..\..\target\release\nwld.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\target\release\nwl.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\target\release\nattowok.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\README.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\LICENSE"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\NattoWok Limiter"; Filename: "{app}\nattowok.exe"
Name: "{group}\Uninstall NattoWok Limiter"; Filename: "{uninstallexe}"
Name: "{autodesktop}\NattoWok Limiter"; Filename: "{app}\nattowok.exe"; Tasks: desktopicon

[Registry]
; Same entry the app's own "start when I log in" setting writes.
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; \
  ValueName: "NattoWok Limiter"; ValueData: """{app}\nattowok.exe"" --hidden"; \
  Flags: uninsdeletevalue; Tasks: autostart

[Run]
Filename: "{app}\nwld.exe"; Parameters: "--install-service"; Flags: runhidden waituntilterminated; \
  StatusMsg: "Starting the NattoWok Limiter service..."
Filename: "{app}\nattowok.exe"; Description: "Open NattoWok Limiter"; \
  Flags: postinstall nowait skipifsilent

[UninstallRun]
Filename: "{app}\nwld.exe"; Parameters: "--uninstall-service"; Flags: runhidden waituntilterminated; \
  RunOnceId: "RemoveService"

[Code]
// Upgrades: stop and remove the running service before files are replaced.
function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  ResultCode: Integer;
begin
  if FileExists(ExpandConstant('{app}\nwld.exe')) then
    Exec(ExpandConstant('{app}\nwld.exe'), '--uninstall-service', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Result := '';
end;
