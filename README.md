# <p align="center">Pasive Port Discovery</p>

<p align="center">A simple automated pasive hosts discovery using the [Telegram Bot API](https://core.telegram.org/bots/api).

## Getting Started

* Install the necessary dependencies (using pip):
```
$ pip install python-nmap 
```

## Usage

Execute the script using all the necessary parameters:

|short argument|long argument|description|
|:---:|: --- :| --- |
|-h| --help| opens the usage |
|-t| --token| token |
|-c| --chat_id| chat identificator where you want to send the messages |
|-o| --output| file where you want to store the json record |
|-i| --ips| ip range to scan. You can use use a list (192.168.100.1,192.168.100.2), a range using the mask (192.168.100.0/24) or simple ips.|
|-p| --ports| ports to scan if the up hosts have the services open. You can use a list (80,22), a range (1-1000) or simple ports |

