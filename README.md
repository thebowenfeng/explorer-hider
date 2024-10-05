# Explorer Hider

DLL that hooks NtQueryDirectoryFile and NtQueryDirectoryFileEx to hide files in file explorer.

## Usage

Inject DLL into any 64-bit instance of file explorer. Specify file names to hide in `HiddenFiles` array. File names are matched via substring matching. Can specify file or folder names.
