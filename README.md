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

## Automating backups
### Windows
Create a `.bat` file similar to this one and schedule it to run once per day using the Task Scheduler:
```
ubuntu.exe run "/home/<user>/tapo-cli/tapo-cli.py download-videos --days 7 --path /mnt/c/TapoBackups --overwrite 0"
```
It requires [WSL](https://learn.microsoft.com/en-us/windows/wsl/install). I also scheduled mine to run at log on.
### Linux

Create a cron task:

```
sudo crontab -e
```

and append a line similar to this one, adjusted for your paths:

```
30 4 * * *  <user> /home/<user>/tapo-cli/tapo-cli.py download-videos --days 7 --path /home/<user>/TapoBackups --overwrite 0
```

It will run at 4:30AM every day.
