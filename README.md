# OVTP

## Description

This module is designed to communicate between servers, transfer messages and files.

The protocol has end-to-end data encryption and client authorization on the server using a key. Passwords are not used. Initially, you need to upload the client key to the server and add it to authorized_keys (can be used --add-keys argument when starting the server).

During transmission, a random key is generated, encrypted using AES encryption, the key is encrypted using the server's public RSA key, and signed with the client's private key. Then, data is transferred, the AES key is decrypted using the server's private key, the data is decrypted using this key, and then the signature is verified using the client's public key. Same thing in reverse.

Public keys are transferred between the client and the server automatically without encryption.

## Requirements
- Python3.7 or higher

## Usage

### Client

An example usage is given in the main.py files in the client and server folders. You can use this module in your script/module that will import ovtp.server. You will need to write your own callback function, which, for example, in server/main.py simply displays the received data on the screen. In your own function, you can do what you need, for example, call some other module and then you need to return 2 values (status and response) that can be obtained from the module you call (for example, that the request is successful and some data).
```python
import asyncio
from ovtp.server import OvtpServer

def callback(status, response):
    print(f'Status: {status}, Response: {response}')
oes = OvtpServer(callback)
asyncio.run(oes.run_server())
```


### Server

On the client side, you need to import ovtp.client, create an OvtpClient instance, and use asyncio.run to call the send_message(your_message) method. You can also send data directly, as well as files.

```python
import asyncio
from ovtp.client import OvtpClient

oec = OvtpClient('127.0.0.1')
asyncio.run(oec.send_message('my_cool_message'))
```

## Описание

Данный модуль создан для связи между серверами, передачи сообщений и файлов.

Протокол обладает сквозным шифрованием данных, а так же авторизацией клиента на сервере с помощью ключа. Пароли не используются. Изначально нужно загрузить ключ клиента на сервер и добавить его в authorized_keys (для этого используется аргумент --add-keys при запуске сервера).

При передаче генерируется случайный ключ, шифруется с использованием AES шифрования, ключ шифруется с помощью открытого RSA ключа сервера и подписывается закрытым ключом клиента. Затем данные передаются, AES ключ расшифровывается с помощью закрытого ключа сервера, расшифровываются данные с помощью этого ключа и затем проверяется подпись с помощью открытого ключа клиента. В обратную сторону то же самое

Открытые ключи передаются между клиентом и сервером в автоматическом режиме в открытом виде.

## Требования
- Python3.7 или выше

## Использование

### Сервер
Использование в качестве примера приведено в файлах main.py в папках client и server. Вы можете использовать данный модуль в своем скрипте/модуле, который будет импортировать ovtp.server. Необходимо будет написать свою callback функцию, которая для примера в server/main.py просто выводит полученные данные на экран. В своей же функции вы можете делать то, что вам необходимо, например вызывать какой-то другой модуль и затем необходимо вернуть 2 значения (status и response), которые могут быть получены из вызываемого вами модуля (например, что запрос успешен и какие-то данные).
```python
import asyncio
from ovtp.server import OvtpServer

def callback(status, response):
    print(f'Status: {status}, Response: {response}')
oes = OvtpServer(callback)
asyncio.run(oes.run_server())
```

### Клиент
Со стороны клиента необходимо импортировать ovtp.client, создать экземпляр OvtpClient и с помощью asyncio.run вызвать метод send_message(ваше_сообщение). Так же можно отправлять данные напрямую, а так же файлы.

```python
import asyncio
from ovtp.client import OvtpClient

oec = OvtpClient('127.0.0.1')
asyncio.run(oec.send_message('my_cool_message'))
```
