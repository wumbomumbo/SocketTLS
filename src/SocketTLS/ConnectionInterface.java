package SocketTLS;

public final class ConnectionInterface {

    public interface ResponseCallback {
        void onResponse(String response);
        void onError(String error);
    }
    
    public interface WebSocketCallback {
        void onConnected();
        void onMessage(String message);
        void onError(String error);
        void onClosed();
    }
    
     // http request
     // method, eg GET, POST, etc.
     // url should be full thing, protocol and everything
     // data mainly for POST requests, if dont need to send data set to null
     // custom headers, leave as null if none, otherwise array of "Header-Name: value"
     // self explanatory

     // btw for wifi and data usage, set via TLSSocketHandler.networkInterface as "wifi" or "data"

    public static void request(
        final String method,
        final String url,
        final String data,
        final String[] headers,
        final ResponseCallback callback
    ) {
        new Thread(new Runnable() {
            public void run() {
                try {
                    URLInfo urlInfo = parseURL(url);
                    
                    // i mean this is for TLS, you might aswell use the native thing if not using https
                    if (!urlInfo.scheme.equals("https")) {
                        if (callback != null) {
                            callback.onError("Only HTTPS is supported");
                        }
                        return;
                    }
                    
                    String response = TLSSocketHandler.httpRequest(
                        urlInfo.host,
                        urlInfo.port,
                        urlInfo.path,
                        method,
                        data,
                        headers
                    );
                    
                    if (callback != null) {
                        callback.onResponse(response);
                    }
                    
                } catch (Exception e) {
                    if (callback != null) {
                        callback.onError(e.toString());
                    }
                }
            }
        }).start();
    }
    
     // websocket connection
     // url should be full thing, protocol and stuff
     // callback for events

    public static WebSocketConnection connectWebSocket(
        final String url,
        final WebSocketCallback callback
    ) {
        try {
            URLInfo urlInfo = parseURL(url);
            
            if (!urlInfo.scheme.equals("wss")) {
                if (callback != null) {
                    callback.onError("Only WSS is supported");
                }
                return null;
            }
            
            return TLSSocketHandler.connectWebSocket(
                urlInfo.host,
                urlInfo.port,
                urlInfo.path,
                callback
            );
            
        } catch (Exception e) {
            if (callback != null) {
                callback.onError(e.toString());
            }
            return null;
        }
    }

    public static interface WebSocketConnection {
        void send(String message);
        void close();
        boolean isConnected();
    }
    
    // helpers for above, unlikely youll need to use these directly
    
    private static class URLInfo {
        String scheme;
        String host;
        int port;
        String path;
    }
    
    private static URLInfo parseURL(String url) throws Exception {
        URLInfo info = new URLInfo();
        
        int schemeEnd = url.indexOf("://");
        if (schemeEnd == -1) {
            throw new Exception("Invalid URL: missing scheme");
        }
        
        info.scheme = url.substring(0, schemeEnd).toLowerCase();
        String remaining = url.substring(schemeEnd + 3);
        
        int pathStart = remaining.indexOf('/');
        String hostPort;
        
        if (pathStart == -1) {
            hostPort = remaining;
            info.path = "/";
        } else {
            hostPort = remaining.substring(0, pathStart);
            info.path = remaining.substring(pathStart);
        }
        
        int portSep = hostPort.indexOf(':');
        if (portSep == -1) {
            info.host = hostPort;
            if (info.scheme.equals("https")) {
                info.port = 443;
            } else if (info.scheme.equals("wss")) {
                info.port = 443;
            } else {
                info.port = 80;
            }
        } else {
            info.host = hostPort.substring(0, portSep);
            info.port = Integer.parseInt(hostPort.substring(portSep + 1));
        }
        
        return info;
    }
}