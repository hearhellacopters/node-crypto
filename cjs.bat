@echo off
setlocal enabledelayedexpansion

cd ./lib/cjs/

set "search=.ts"
set "replace=.cts"

for %%f in (*%search%) do (
    set "fullfilename=%%~nxf"
    set "newfilename=!fullfilename:%search%=%replace%!"
    ren "%%f" "!newfilename!"
)

set "search=.ts.map"
set "replace=.cts.map"

for %%f in (*%search%) do (
    set "fullfilename=%%~nxf"
    set "newfilename=!fullfilename:%search%=%replace%!"
    ren "%%f" "!newfilename!"
)

set "search=.js"
set "replace=.cjs"

for %%f in (*%search%) do (
    set "fullfilename=%%~nxf"
    set "newfilename=!fullfilename:%search%=%replace%!"
    ren "%%f" "!newfilename!"
)

set "search=.js.map"
set "replace=.cjs.map"

for %%f in (*%search%) do (
    set "fullfilename=%%~nxf"
    set "newfilename=!fullfilename:%search%=%replace%!"
    ren "%%f" "!newfilename!"
)

endlocal