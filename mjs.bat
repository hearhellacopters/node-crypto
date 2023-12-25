@echo off
setlocal enabledelayedexpansion

cd ./lib/esm/

set "search=.ts"
set "replace=.mts"

for %%f in (*%search%) do (
    set "fullfilename=%%~nxf"
    set "newfilename=!fullfilename:%search%=%replace%!"
    ren "%%f" "!newfilename!"
)

set "search=.ts.map"
set "replace=.mts.map"

for %%f in (*%search%) do (
    set "fullfilename=%%~nxf"
    set "newfilename=!fullfilename:%search%=%replace%!"
    ren "%%f" "!newfilename!"
)

set "search=.js"
set "replace=.mjs"

for %%f in (*%search%) do (
    set "fullfilename=%%~nxf"
    set "newfilename=!fullfilename:%search%=%replace%!"
    ren "%%f" "!newfilename!"
)

set "search=.js.map"
set "replace=.mjs.map"

for %%f in (*%search%) do (
    set "fullfilename=%%~nxf"
    set "newfilename=!fullfilename:%search%=%replace%!"
    ren "%%f" "!newfilename!"
)

endlocal