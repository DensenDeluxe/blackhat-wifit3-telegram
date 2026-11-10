# Blackhat wifit3 Telegram Bridge

Runs wifit3 on Blackhat OS and sends capture and recovered PSK notifications to Telegram using the existing `/mnt/blackhat.conf` configuration.

## Install wifit3

wifit3 is a Python application and does not require a separate compilation step.

```bash
apt update
apt install -y git python3 python3-venv python3-dev libusb-1.0-0
cd /root
git clone https://github.com/derv82/wifit3.git
cd wifit3
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -e .
```

## Install the bridge

```bash
cp telegram_wifit3.py /mnt/scripts/telegram_wifit3.py
chmod +x /mnt/scripts/telegram_wifit3.py
```

The Telegram helper reads `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID` from `/mnt/blackhat.conf`.

## Run

```bash
/mnt/scripts/telegram_wifit3.py
```

The bridge forwards normal wifit3 command-line arguments and sends handshake, PMKID, WPS PSK, and successful crack-job notifications. It does not provide Telegram commands for wireless actions.

