# Prepare a private output directory on Windows or macOS

**Current status: macOS output is enabled after native amd64/arm64 privacy
qualification; Windows output remains disabled pending native qualification.**
These instructions prepare an ordinary user's directory; they do not enable a
disabled binary or establish native provider acceptance.
Authored platform tests and cross-compilation are separate from successful
native CI execution. The CLI needs no provider login or administrator account
for ordinary output.

First check the binary you intend to use:

```powershell
.\pwmigrate-go.exe version --json
.\pwmigrate-go.exe formats --json
```

On macOS use `./pwmigrate-go`. Read the top-level
`output_platform_supported` value from `formats --json`. A value of `false`
means `convert`, `recovery-key`, `recovery-save` and `recover` refuse output with
`output_platform`, even when your directory is private. Wait for a reviewed,
qualified build whose public output capability is enabled; do not bypass the
guard using development APIs. Inspection, planning and supplied re-export
comparison remain available.

Use synthetic data while qualifying a build. Destination exports and restored
sources can be plaintext. Keep recovery keys separately, and never put an export
password or secret age key in argv, shell history or a report. The directory
examples below contain no vault data or key material.

## Windows: create a new protected NTFS directory

Use an existing normal directory on a **local fixed NTFS volume**, under your
own Windows profile. Network/UNC paths, removable drives, FAT/exFAT, junctions,
symlinks and other reparse points are refused by the candidate writer. Existing
ancestors must also be ordinary directories. A folder's read-only checkbox and
a Unix-style mode argument do not establish Windows privacy.

The current source requires the final output parent to be owned by your current
SID, have a protected DACL, and contain exactly the current-user and LocalSystem
full-control allow rules. It accepts no inherited rules, Administrator/Everyone
rules, deny rules or ACE inheritance flags. Each generated child receives its
own protected private descriptor, so parent rules do **not** need inheritance.

Open the built-in **Windows PowerShell 5.1** as your ordinary user. If your
terminal currently runs PowerShell 7, start `powershell.exe -NoProfile`; no new
PowerShell installation or administrator elevation is needed. This recipe uses
the built-in .NET Framework directory/security overloads available there.

Choose a new output name. The default below uses your existing local application
data directory. If that location is redirected or contains a reparse point,
choose an ordinary existing local NTFS directory instead. Edit only the quoted
directory choice, then run this block:

```powershell
$ErrorActionPreference = 'Stop'
$baseDirectory = [System.IO.Path]::GetFullPath($env:LOCALAPPDATA)
$outputParent = [System.IO.Path]::Combine($baseDirectory, 'pwmigrate-output')

if (-not [System.IO.Directory]::Exists($baseDirectory)) {
    throw 'The chosen base directory must already exist.'
}
if (Test-Path -LiteralPath $outputParent) {
    throw 'The output directory already exists. Choose a new name.'
}

$currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
$systemSid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-18')
$security = [System.Security.AccessControl.DirectorySecurity]::new()
$security.SetOwner($currentSid)
$security.SetAccessRuleProtection($true, $false)

foreach ($sid in @($currentSid, $systemSid)) {
    $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
        $sid,
        [System.Security.AccessControl.FileSystemRights]::FullControl,
        [System.Security.AccessControl.InheritanceFlags]::None,
        [System.Security.AccessControl.PropagationFlags]::None,
        [System.Security.AccessControl.AccessControlType]::Allow
    )
    $security.AddAccessRule($rule)
}

$stagingDirectory = [System.IO.Path]::Combine(
    $baseDirectory, 'pwmigrate-parent-' + [System.Guid]::NewGuid().ToString('N')
)
if (Test-Path -LiteralPath $stagingDirectory) {
    throw 'The staging directory already exists. Try a fresh attempt.'
}
[System.IO.Directory]::CreateDirectory($stagingDirectory, $security) | Out-Null
[System.IO.Directory]::Move($stagingDirectory, $outputParent)

$acl = [System.IO.Directory]::GetAccessControl($outputParent)
$owner = $acl.GetOwner([System.Security.Principal.SecurityIdentifier])
$rules = $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])
if ($owner.Value -ne $currentSid.Value -or -not $acl.AreAccessRulesProtected -or $rules.Count -ne 2) {
    throw 'The created directory did not pass the private ACL check.'
}
foreach ($rule in $rules) {
    if ($rule.IsInherited -or
        $rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow -or
        $rule.FileSystemRights -ne [System.Security.AccessControl.FileSystemRights]::FullControl -or
        $rule.InheritanceFlags -ne [System.Security.AccessControl.InheritanceFlags]::None -or
        $rule.PropagationFlags -ne [System.Security.AccessControl.PropagationFlags]::None -or
        ($rule.IdentityReference.Value -ne $currentSid.Value -and $rule.IdentityReference.Value -ne $systemSid.Value)) {
        throw 'The created directory has an unexpected access rule.'
    }
}
```

The protected security descriptor is supplied **at creation**, rather than
creating an exposed directory and tightening it later. A fresh staging name is
renamed to the desired new path; `Directory.Move` refuses an existing target.
No existing directory's ACL or contents are replaced. If creation/rename/checks
fail, a private staging or final directory may remain. Inspect it locally and
choose a fresh name; this block performs no automatic cleanup.

The ACL check above is a useful local check, not proof of the volume/reparse
policy or isolation from administrators, LocalSystem or other processes using
your own account. The writer checks opened native handles and rejects unsuitable
ancestors/volumes. Do not weaken the DACL or add inherited rules to work around
`output_parent`. Local account SIDs and paths need not be posted in a public
qualification result.

After the public writer has been qualified and enabled, use the same terminal's
`$outputParent` variable as the argument:

```powershell
.\pwmigrate-go.exe inspect --input 'synthetic source.json' --from bitwarden-json
.\pwmigrate-go.exe plan --input 'synthetic source.json' --to onepassword-1pux
.\pwmigrate-go.exe convert --input 'synthetic source.json' --to onepassword-1pux --output-dir $outputParent
```

Read every issue and enter the exact current `approve REVIEW_ID ISSUE_ID ...`
line. Require exit code 0 and the successful receipt before importing. The
receipt's `job_directory` and `file_name` identify the artifact relative to
`$outputParent`. Opening a fresh terminal does not retain that variable; use
the same quoted directory path explicitly there.

## macOS: create a new directory with no extended ACL

Use your ordinary account on a writable **local APFS or HFS+ volume with
ownership enabled**. Ownership-disabled, read-only, network and unsupported
filesystems fail closed. A directory must belong to the effective user, have
no group/other write permission and no extended ACL. The private generated job
directories and files are checked separately. A deny-only ACL is still an ACL
and is refused by this profile.

This block creates a new directory under your home and removes an inherited
extended ACL only from that newly created directory. `mkdir` has no `-p`:
if the selected path already exists, it fails and the later commands do not run.
Choose a new name instead of changing an existing directory's permissions.

```sh
(
  set -eu
  task_output_parent="$HOME/pwmigrate-output"
  umask 077
  mkdir -m 700 "$task_output_parent"
  chmod -N "$task_output_parent"
  chmod 700 "$task_output_parent"
  test "$(stat -f '%u' "$task_output_parent")" = "$(id -u)"
  ls -lde "$task_output_parent"
  task_volume_device="$(df -P "$task_output_parent" | awk 'NR == 2 {print $1}')"
  test -n "$task_volume_device"
  diskutil info "$task_volume_device"
)
```

Check locally that the directory is owned by your user, has `drwx------`
permissions and shows no numbered extended-ACL entries. The volume information
must identify local APFS/HFS+, ownership enabled and a writable volume. The
writer's native handle checks are the final decision; do not change volume
ownership or mount policy to bypass a rejection. If this setup fails, retain
the directory privately and investigate before retrying with a fresh name.

After the public writer has been qualified and enabled:

```sh
./pwmigrate-go inspect --input "synthetic source.json" --from bitwarden-json
./pwmigrate-go plan --input "synthetic source.json" --to onepassword-1pux
./pwmigrate-go convert --input "synthetic source.json" --to onepassword-1pux --output-dir "$HOME/pwmigrate-output"
```

Review the current approval instruction and all its issues. Require exit 0 and
the successful receipt; its generated basename/filename are relative to that
output parent. Failed or cancelled jobs may retain private partial artifacts
or a complete file if a later step/report fails. Inspect them locally before
retrying; a retry uses a new job and requires fresh approval.

## Paths, passwords, recovery and destination checks

Quote source and output paths containing spaces. Most terminals insert a path
when a file is dragged onto the command line; inspect the resulting quoting
before running the command. Dragging onto an executable/file-drop launching is
not a CLI migration journey.

Supported encrypted input prompts locally with echo disabled. Controlled stdin
can use `--password-stdin --password-json` for exact CR/LF/Unicode passwords;
the password is one JSON-string line followed by the current conversion approval
line. An existing age key is supplied by **file path** with
`--recovery-key-file` or `--key-file`, not by placing its secret contents in argv.
Create a separate private key directory using the same platform preparation
procedure. Whole-source recovery includes excluded records and unsupported
data; it is preserved, not migrated. Losing the separately stored key makes
recovery unreadable.

The export/recovery job is not one atomic filesystem transaction. A nonzero
exit or missing success receipt does not authorize importing a leftover file.
There is no automatic source deletion, retry or secure-erasure guarantee.
Private permissions do not isolate administrators/root, LocalSystem or
same-user processes.

Once output succeeds, manually import the successful **synthetic** artifact
into a disposable empty destination vault, then supply its native re-export to
`compare`. Follow the [provider qualification checklist](provider-qualification.md)
and [synthetic qualification kit](qualification-kit.md). A private successful
write, a supplied comparison and provider-native acceptance are separate
results; none alone proves working passkeys or SSH authentication.

## Evidence and enablement

The requirements above follow the current
[Windows descriptor policy](../../internal/protectedoutput/security_policy.go),
[Windows native handle/volume checks](../../internal/protectedoutput/native_windows.go),
[Windows writer](../../internal/protectedoutput/output_windows.go) and
[macOS privacy checks](../../internal/protectedoutput/output_darwin.go).
The Windows writer returns `output_platform` publicly until native qualification
passes. macOS privacy qualification passed on amd64 and arm64 before public
enablement; fresh public CLI conversion/recovery journeys must be recorded for
the enabled candidate. Ordinary-user parent preparation and public CLI output
need native evidence for the exact reviewed candidate.
The Windows fixture uses equivalent current-token native directory/security
APIs; it does not execute this PowerShell/.NET recipe. The command recipes have
source/static review only until native execution is recorded.

Retain a sanitized record of OS/architecture/filesystem, converter version and
public source commit, public `output_platform_supported` value, ordinary-user
setup outcome, native permission/no-clobber/cancellation/failure checks and
packaged-binary smoke result. Do not attach personal paths, SIDs, source values,
passwords, keys or source-derived fingerprints. Cross-compilation and static
review are authored evidence only; actual native execution remains pending
until a recorded passing run establishes it.
