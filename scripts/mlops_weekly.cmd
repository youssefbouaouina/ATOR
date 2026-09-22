@echo off
rem Weekly MLOps run, as started by the "ATOR ML Weekly Update" scheduled task.
rem Portable: resolves the repository from this script's own location, so the task works
rem wherever the repo is cloned. Output goes to mlops\scheduler.log so that even a failure
rem to start Python (broken venv, missing package) leaves a trace; the pipeline's own
rem per-run log and report are in mlops\runs\<run id>\.
rem Exit code is the pipeline's: 0 ok, 1 failed (models unchanged), 2 needs a look.
setlocal
set "REPO=%~dp0.."
pushd "%REPO%" || exit /b 1
if not exist "mlops" mkdir "mlops"
set "PY=%REPO%\.venv\Scripts\python.exe"
if not exist "%PY%" (
    >> "mlops\scheduler.log" echo %DATE% %TIME% ERROR: %PY% not found - rebuild the venv, see docs/ML_PROGRESS.md
    popd
    exit /b 1
)
>> "mlops\scheduler.log" echo %DATE% %TIME% starting weekly MLOps run
"%PY%" -m ml.mlops run --trigger schedule >> "mlops\scheduler.log" 2>&1
set "RC=%ERRORLEVEL%"
rem Redirection first: "%RC%>>" would make cmd read the exit code as a stream handle number.
>> "mlops\scheduler.log" echo %DATE% %TIME% finished with exit code %RC%
popd
exit /b %RC%
