This folder containts tests for Windows version of tvc.
tests.exe has the following bugs:
   1. Buffer overflow (routine return address overwrite in stack)
   2. Heap incorrect use (allocated heap used in the routine that couldn't access to it)
   3. Stack use after return 