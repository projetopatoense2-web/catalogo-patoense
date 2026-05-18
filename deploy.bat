@echo off
cd /d "%~dp0"
echo === DEPLOY - CATALOGO PATOENSE ===
echo.
git add .
echo.
set /p MSG="Descricao da atualizacao: "
echo.
git commit -m "%MSG%"
git push
echo.
echo === DEPLOY CONCLUIDO! ===
pause
