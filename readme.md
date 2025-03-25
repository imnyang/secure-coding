# Secure Coding

## Tiny Secondhand Shopping Platform.

You should add some functions and complete the security requirements.

## requirements

if you don't have a miniconda(or anaconda), you can install it on this url. - https://docs.anaconda.com/free/miniconda/index.html

```
git clone https://github.com/ugonfor/secure-coding && cd secure-coding 
conda env create -f enviroments.yaml
conda activate secure_coding
```

## usage

run the server process.

```
python3 app.py
```

if you want to test on external machine, you can utilize the ngrok to forwarding the url.
```
# optional
sudo snap install ngrok
ngrok http 5000
```