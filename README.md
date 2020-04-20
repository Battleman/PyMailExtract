# PyMailExtract
Extracts all the email present in the headers or body in a Gmail mailbox

## How to make it work ?
First of all, install the python requirements. This code was written for python 3.6. You can use virtualEnv, conda, pip or whatever you fancy. The packages that are not in a basic python install are listed in `requirements.txt`. You can input this file to pip.

Then, you need to enable API in your Gmail account.
For that, go to [this URL](https://developers.google.com/gmail/api/quickstart/python) and follow step 1.
Once that you have obtained the file `credentials.json`, place it at the same place than the script

At this point, you can just launch the code (on a computer with a visual interface):
`python3 Pymailextract.py` 
Your browser will open a window to chose the google account you wish to use, and identify yourself.
Once this is done, you can close the browser tab, and the code will run. Next runs won't require to log in the browser.

## Support
Like this project? Consider supporting me, for more awesome updates

<a class="bmc-button" target="_blank" href="https://www.buymeacoffee.com/Battleman"><img src="https://cdn.buymeacoffee.com/buttons/bmc-new-btn-logo.svg" alt="Buy me a coffee"><span style="margin-left:15px;font-size:28px !important;">Buy me a coffee</span></a>
