@echo off
REM Set the PowerShell execution policy to RemoteSigned for the current process
powershell -Command "Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process"

REM Activate the virtual environment using activate.bat (for batch files)
call venv\Scripts\activate.bat


REM Install dependencies from requirements.txt
pip install -r requirements.txt

REM Run your Python script 
python virustotal.py

REM Optionally, open the HTML file 
start .\templates\file.html

REM Keep the terminal open if you need to see any output
pause
