:: Prevent commands from being displayed. The @ symbol hides this command from view as well.
@echo off 
py ICMPpinger.py "www.google.com"
:: Prevent the command window from closing immediately, displaying the prompt: Press any key to continue . . .
pause 