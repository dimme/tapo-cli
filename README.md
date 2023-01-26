# tapo-cli
Command-line utility for batch-downloading your videos from the Tapo TP-Link Cloud.

This has not been tested on Windows, use [WSL](https://learn.microsoft.com/en-us/windows/wsl/install).

It should work fine one any Debian-based OS with `python3` and `pip3` installed.

## How to use
```
git clone https://github.com/dimme/tapo-cli.git
cd tapo-cli
pip3 install -r requirements.txt
chmod +x tapo-cli.py
./tapo-cli.py login
./tapo-cli.py list-videos
./tapo-cli.py download-videos
```

For more stuff check `./tapo-cli.py --help` and `./tapo-cli.py [COMMAND] --help`
