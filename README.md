# SocketTLS

---

## A library for communicating over TLS 1.0 up to 1.2 on BlackBerry OS devices

SocketTLS is a library for BlackBerry OS (7.1) devices that allows apps to communicate over TLS (up to 1.2), instead of being limited to the native TLS 1.0 support provided by the OS.

---

### How it works

This library is built on top of the legacy BouncyCastle J2ME API, which has been modified to work within the limitations of BBOS, and SocketTLS provides a premade interface for easy usage in apps. It also does not require the app to be signed, as it avoids using any restricted methods.

---

### How to build

The build process is pretty simple, in this guide we'll be going over the way I do it.

You'll want to install the [BlackBerry Eclipse Plugin](https://archive.org/download/java-for-blackberryos/Eclipse%20Plug-in/). The installer will automatically install the correct version of Eclipse for your system, you will also want to install JDK 1.5 32-Bit.

I won't go into detail on setting up everything with Eclipse, any issues you encounter you can probably fix with some googling.

Building SocketTLS should be simple as including it as a library within your project, or packaging SocketTLS, which should output a JAR file that you can use.

You may have issues with Eclipse running out of memory upon building SocketTLS, you may need to increase the default memory settings.

---

### Usage

HTTPS Example:

```java
ConnectionInterface.request(
    method,
    url,
    null,
    null,
    new ConnectionInterface.ResponseCallback() {
        public void onResponse(String response) {
            appendText(response);
        }

        public void onError(String error) {
            appendText("ERROR: " + error);
        }
    }
);
```

WSS Example:

```java
ConnectionInterface.connectWebSocket(
    url,
    new ConnectionInterface.WebSocketCallback() {

        public void onConnected() {
            appendText("WebSocket connected");
        }

        public void onMessage(String message) {
            appendText("Message: " + message);
        }

        public void onError(String error) {
            appendText("ERROR: " + error);
        }

        public void onClosed() {
            appendText("WebSocket closed");
        }
    }
);
```
---

### Notes

> This library is in early access, it may be unstable or cause slowdowns.

> This library is created specifically for BlackBerry OS 7.1, as of right now lower versions have not been tested, other devices may also be able to use this library but that is also yet to be determined.

> Artificial Intelligence was partially used in the creation of this library.

---

### Credits

Feel free to use and modify this library as per the MIT License. Credit would be appreciated :)
