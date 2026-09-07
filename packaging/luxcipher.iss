; Inno Setup script for LuxCipher.
;
; Build with:
;   iscc packaging\luxcipher.iss /DAppVersion=0.1.0 /DSourceDir=..\build\windows
;
; Two deliberate choices are load bearing, please read before changing them.
;
; 1. This is a per-user install (PrivilegesRequired=lowest) into
;    {localappdata}\Programs\LuxCipher, not Program Files. It needs no
;    administrator rights, and it keeps the installed program in the same
;    per-user tree as the data it works with.
;
; 2. The uninstaller does NOT remove {localappdata}\LuxCipher. That directory
;    holds vault.db and vault.salt, which are the user's entire password
;    collection. There is no recovery path for them: no cloud copy, no export,
;    no password reset. Deleting them on uninstall would destroy user data
;    that cannot be reconstructed, so it must never be added here, not even
;    behind a checkbox that defaults to on.

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif

#ifndef SourceDir
  #define SourceDir "..\build\windows"
#endif

#define AppName "LuxCipher"
#define AppPublisher "LuxCipher"
#define AppExeName "LuxCipher.exe"
#define VaultDir "{localappdata}\LuxCipher"

[Setup]
; Keep this GUID stable forever: it is how Windows recognises an upgrade of an
; existing install rather than a second, parallel one.
AppId={{73910280-A2F2-4726-BFE0-868CE4B3D9E9}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppPublisher}
VersionInfoVersion={#AppVersion}

DefaultDirName={localappdata}\Programs\{#AppName}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible

OutputDir=..\dist
OutputBaseFilename={#AppName}-{#AppVersion}-setup
UninstallDisplayName={#AppName}
UninstallDisplayIcon={app}\{#AppExeName}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern

[Languages]
Name: "italian"; MessagesFile: "compiler:Languages\Italian.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[Files]
Source: "{#SourceDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExeName}"
Name: "{userdesktop}\{#AppName}"; Filename: "{app}\{#AppExeName}"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Run]
Filename: "{app}\{#AppExeName}"; Description: "{cm:LaunchProgram,{#AppName}}"; Flags: nowait postinstall skipifsilent

; No [UninstallDelete] section. Uninstalling removes the program from {app}
; and leaves the vault in {#VaultDir} untouched, so reinstalling finds the
; existing passwords. See the note at the top of this file.

[Code]
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  VaultPath: String;
begin
  if CurUninstallStep = usPostUninstall then
  begin
    VaultPath := ExpandConstant('{#VaultDir}');
    if DirExists(VaultPath) then
      MsgBox('LuxCipher è stato disinstallato.' #13#13
             'Le tue password NON sono state cancellate e si trovano ancora in:' #13
             + VaultPath + #13#13
             'Reinstallando LuxCipher le ritroverai. Se vuoi eliminarle '
             'definitivamente devi cancellare quella cartella a mano: '
             'non esiste alcun modo di recuperarle dopo.',
             mbInformation, MB_OK);
  end;
end;
