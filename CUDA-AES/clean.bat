del /q *.xml
del /q *.sdf
del /q *.html

del /q CUDAWinDemo\*.pdb
del /q CUDAWinDemo\*.enc
del /q CUDAWinDemo\*.changeme

rd /s /q _UpgradeReport_Files
rd /s /q ipch
rd /s /q Debug
rd /s /q Release
rd /s /q x64

rd /s /q CUDAWinDemo\Debug
rd /s /q CUDAWinDemo\Release
rd /s /q CUDAWinDemo\x64

pause

