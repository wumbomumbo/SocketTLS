package SocketTLS;

import java.io.InputStream;
import java.io.OutputStream;
import java.io.IOException;
import java.util.Hashtable;
import java.util.Vector;

import javax.microedition.io.Connector;
import javax.microedition.io.SocketConnection;

import org.bouncycastle.crypto.tls.TlsClientProtocol;
import org.bouncycastle.crypto.tls.DefaultTlsClient;
import org.bouncycastle.crypto.tls.TlsAuthentication;
import org.bouncycastle.crypto.tls.TlsCredentials;
import org.bouncycastle.crypto.tls.Certificate;
import org.bouncycastle.crypto.tls.CertificateRequest;
import org.bouncycastle.crypto.tls.TlsExtensionsUtils;
import org.bouncycastle.crypto.tls.ServerName;
import org.bouncycastle.crypto.tls.ServerNameList;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.DERIA5String;

import bcjavastub.security.SecureRandom;

// handler for connection via TLS, please use ConnectionHandler for easier access

public final class TLSSocketHandler {
    
    // default user agent, can be changed if needed

    public static String userAgent = "BlackBerry-TLS-Client/1.0";
    public static String networkInterface = "wifi";
    public static boolean stripHeaders = true;
    
    // look at connectioninterface for reference, similar usage
    static String httpRequest(
        final String host,
        final int port,
        final String path,
        final String method,
        final String data,
        final String[] customHeaders
    ) throws Exception {
        
        SocketConnection sc = null;
        TlsClientProtocol protocol = null;

        try {
            if (TLSConstants.DebugMode) {
                System.out.println("DEBUG: Connecting to " + host + ":" + port);
            }

            sc = (SocketConnection) Connector.open(
                buildConnectionString(host, port)
            );

            InputStream in = sc.openInputStream();
            OutputStream out = sc.openOutputStream();
            SecureRandom random = new SecureRandom();
            
            protocol = new TlsClientProtocol(in, out, random);
            protocol.connect(createTlsClient(host));

            InputStream tlsIn = protocol.getInputStream();
            OutputStream tlsOut = protocol.getOutputStream();

            StringBuffer req = new StringBuffer();
            req.append(method).append(" ").append(path).append(" HTTP/1.1\r\n");
            req.append("Host: ").append(host).append("\r\n");

            if (!hasUserAgent(customHeaders)) {
                req.append("User-Agent: ").append(userAgent).append("\r\n");
            }

            if (customHeaders != null) {
                for (int i = 0; i < customHeaders.length; i++) {
                    req.append(customHeaders[i]).append("\r\n");
                }
            }
            
            if (data != null && data.length() > 0) {
                if (req.toString().indexOf("Content-Length:") == -1) {
                    req.append("Content-Length: ").append(data.length()).append("\r\n");
                }
                if (req.toString().indexOf("Content-Type:") == -1) {
                    req.append("Content-Type: application/x-www-form-urlencoded\r\n");
                }
            }
            
            req.append("Connection: close\r\n");
            req.append("\r\n");
            
            if (data != null && data.length() > 0) {
                req.append(data);
            }

            tlsOut.write(req.toString().getBytes("UTF-8"));
            tlsOut.flush();

            byte[] buf = new byte[1024];
            StringBuffer resp = new StringBuffer();

            try {
                while (true) {
                    int r = tlsIn.read(buf);
                    if (r == -1) {
                        break;
                    }
                    resp.append(new String(buf, 0, r, "UTF-8"));
                }
            } catch (IOException e) {
                // hack, just makes it seem less bad and wont take the whole thing down
                if (TLSConstants.DebugMode) {
                    System.out.println("DEBUG: Read finished (socket closed)");
                }
            }

            protocol.close();
            sc.close();

            String response = resp.toString();
            boolean isChunked = response.toLowerCase().indexOf("transfer-encoding: chunked") != -1;
            String headers = "";
            
            int headerEnd = response.indexOf("\r\n\r\n");
            if (headerEnd != -1) {
                headers = response.substring(0, headerEnd + 4);
            } else {
                headerEnd = response.indexOf("\n\n");
                if (headerEnd != -1) {
                    headers = response.substring(0, headerEnd + 2);
                }
            }
            
            // decoding chunked in wrong scenario will fuck things up

            if (isChunked) {
                response = stripHttpHeaders(response);
                try {
                    response = decodeChunkedEncoding(response);
                } catch (Exception e) {
                    // if fails, might as well return what we have
                }
            } else if (stripHeaders) {
                response = stripHttpHeaders(response);
            }
            
            if (!stripHeaders && isChunked) {
                response = headers + response;
            }
            
            return response;

        } catch (Exception e) {
            if (protocol != null) {
                try { protocol.close(); } catch (Exception ignored) {}
            }
            if (sc != null) {
                try { sc.close(); } catch (Exception ignored) {}
            }
            throw e;
        }
    }
    

    static ConnectionInterface.WebSocketConnection connectWebSocket(
        final String host,
        final int port,
        final String path,
        final ConnectionInterface.WebSocketCallback callback
    ) {
        
        final WebSocketConnectionImpl conn = new WebSocketConnectionImpl();
        
        new Thread(new Runnable() {
            public void run() {
                SocketConnection sc = null;
                TlsClientProtocol protocol = null;
                
                try {
                    if (TLSConstants.DebugMode) {
                        System.out.println("DEBUG: Connecting WebSocket to " + host + ":" + port);
                    }

                    sc = (SocketConnection) Connector.open(
                        buildConnectionString(host, port)
                    );

                    InputStream in = sc.openInputStream();
                    OutputStream out = sc.openOutputStream();
                    SecureRandom random = new SecureRandom();
                    
                    protocol = new TlsClientProtocol(in, out, random);
                    protocol.connect(createTlsClient(host));

                    InputStream tlsIn = protocol.getInputStream();
                    OutputStream tlsOut = protocol.getOutputStream();

                    byte[] keyBytes = new byte[16];
                    random.nextBytes(keyBytes);

                    byte[] wsKeyBytes = Base64.encode(keyBytes);
                    String wsKey = new String(wsKeyBytes);

                    String uaHeader = "User-Agent: " + userAgent + "\r\n";

                    String req =
                        "GET " + path + " HTTP/1.1\r\n" +
                        "Host: " + host + "\r\n" +
                        "Upgrade: websocket\r\n" +
                        "Connection: Upgrade\r\n" +
                        "Sec-WebSocket-Key: " + wsKey + "\r\n" +
                        "Sec-WebSocket-Version: 13\r\n" +
                        uaHeader +
                        "\r\n";

                    tlsOut.write(req.getBytes("UTF-8"));
                    tlsOut.flush();

                    byte[] buf = new byte[1024];
                    StringBuffer response = new StringBuffer();

                    try {
                        while (true) {
                            int r = tlsIn.read(buf);
                            if (r == -1) {
                                break;
                            }

                            response.append(new String(buf, 0, r, "UTF-8"));

                            if (response.toString().indexOf("\r\n\r\n") != -1) {
                                break;
                            }
                        }
                    } catch (IOException e) {

                    }

                    String handshakeResp = response.toString();

                    if (handshakeResp.indexOf("101") == -1 ||
                        handshakeResp.toLowerCase().indexOf("upgrade: websocket") == -1) {
                        throw new IOException("WebSocket handshake failed");
                    }

                    conn.setStreams(tlsIn, tlsOut, protocol, sc);
                    
                    if (callback != null) {
                        callback.onConnected();
                    }

                    while (conn.isConnected()) {
                        try {
                            String message = readWebSocketFrame(tlsIn);
                            if (message != null && callback != null) {
                                callback.onMessage(message);
                            }
                        } catch (IOException e) {
                            break;
                        }
                    }

                    if (callback != null) {
                        callback.onClosed();
                    }

                } catch (Exception e) {
                    if (callback != null) {
                        callback.onError(e.toString());
                    }
                } finally {
                    conn.cleanup();
                }
            }
        }).start();
        
        return conn;
    }

    private static class WebSocketConnectionImpl implements ConnectionInterface.WebSocketConnection {
        private InputStream in;
        private OutputStream out;
        private TlsClientProtocol protocol;
        private SocketConnection socket;
        private boolean connected = false;
        
        void setStreams(InputStream in, OutputStream out, TlsClientProtocol protocol, SocketConnection socket) {
            this.in = in;
            this.out = out;
            this.protocol = protocol;
            this.socket = socket;
            this.connected = true;
        }
        
        public void send(String message) {
            if (!connected) return;
            
            try {
                sendWebSocketFrame(out, message);
            } catch (IOException e) {
                connected = false;
            }
        }
        
        public void close() {
            connected = false;
            cleanup();
        }
        
        public boolean isConnected() {
            return connected;
        }
        
        void cleanup() {
            try {
                if (protocol != null) protocol.close();
                if (socket != null) socket.close();
            } catch (Exception e) {
            }
        }
    }
    
    // basic security features, better than nothing at least
    private static DefaultTlsClient createTlsClient(final String host) {
        return new DefaultTlsClient() {

            public Hashtable getClientExtensions() throws IOException {
                Hashtable ext = super.getClientExtensions();
                if (ext == null) {
                    ext = new Hashtable();
                }
                
                if (!ext.containsKey(TlsExtensionsUtils.EXT_server_name)) {
                    if (!isIPAddress(host)) {
                        Vector serverNames = new Vector();
                        serverNames.addElement(new ServerName((short)0, host));
                        ServerNameList snl = new ServerNameList(serverNames);
                        ext.put(
                            TlsExtensionsUtils.EXT_server_name,
                            TlsExtensionsUtils.createServerNameExtension(snl)
                        );
                    }
                }
                
                return ext;
            }

            public TlsAuthentication getAuthentication() {
                return new TlsAuthentication() {
                    public void notifyServerCertificate(Certificate serverCertificate) 
                        throws IOException {
                        if (serverCertificate == null || serverCertificate.isEmpty()) {
                            throw new IOException("Server sent no certificate");
                        }
                        
                        org.bouncycastle.asn1.x509.Certificate cert = 
                            serverCertificate.getCertificateAt(0);
                        
                        if (!validateDates(cert)) {
                            throw new IOException("Certificate expired or not yet valid");
                        }
                        
                        if (!validateHostname(cert, host)) {
                            throw new IOException("Certificate hostname mismatch! Expected: " + host);
                        }
                    }

                    public TlsCredentials getClientCredentials(CertificateRequest cr) {
                        return null;
                    }
                };
            }
        };
    }

    // wont lie no fucking clue how this works, black magic 

    private static void sendWebSocketFrame(OutputStream out, String message) throws IOException {
        byte[] payload = message.getBytes("UTF-8");
        int payloadLen = payload.length;
        
        byte[] maskKey = new byte[4];
        SecureRandom rand = new SecureRandom();
        rand.nextBytes(maskKey);
        
        int frameSize = 2 + 4 + payloadLen;
        if (payloadLen > 125) {
            frameSize += 2;
        }
        
        byte[] frame = new byte[frameSize];
        int pos = 0;
        
        frame[pos++] = (byte) 0x81;
        
        if (payloadLen <= 125) {
            frame[pos++] = (byte) (0x80 | payloadLen);
        } else {
            frame[pos++] = (byte) (0x80 | 126);
            frame[pos++] = (byte) ((payloadLen >> 8) & 0xFF);
            frame[pos++] = (byte) (payloadLen & 0xFF);
        }
        
        frame[pos++] = maskKey[0];
        frame[pos++] = maskKey[1];
        frame[pos++] = maskKey[2];
        frame[pos++] = maskKey[3];
        
        for (int i = 0; i < payloadLen; i++) {
            frame[pos++] = (byte) (payload[i] ^ maskKey[i % 4]);
        }
        
        out.write(frame);
        out.flush();
    }
    
    private static String readWebSocketFrame(InputStream in) throws IOException {
        int b1 = in.read();
        int b2 = in.read();
        
        if (b1 == -1 || b2 == -1) {
            throw new IOException("Connection closed");
        }
        
        int opcode = b1 & 0x0F;
        boolean masked = (b2 & 0x80) != 0;
        int payloadLen = b2 & 0x7F;
        
        if (payloadLen == 126) {
            int len1 = in.read();
            int len2 = in.read();
            payloadLen = ((len1 & 0xFF) << 8) | (len2 & 0xFF);
        } else if (payloadLen == 127) {
            throw new IOException("Payload too large");
        }
        
        byte[] maskKey = null;
        if (masked) {
            maskKey = new byte[4];
            in.read(maskKey);
        }
        
        byte[] payload = new byte[payloadLen];
        int totalRead = 0;
        while (totalRead < payloadLen) {
            int r = in.read(payload, totalRead, payloadLen - totalRead);
            if (r == -1) break;
            totalRead += r;
        }
        
        if (masked) {
            for (int i = 0; i < payloadLen; i++) {
                payload[i] = (byte) (payload[i] ^ maskKey[i % 4]);
            }
        }
        
        return new String(payload, "UTF-8");
    }
    
    // utilities for validation
    
    private static boolean validateDates(org.bouncycastle.asn1.x509.Certificate cert) {
        try {
            long now = System.currentTimeMillis();
            long notBefore = cert.getStartDate().getDate().getTime();
            long notAfter = cert.getEndDate().getDate().getTime();
            return now >= notBefore && now <= notAfter;
        } catch (Exception e) {
            return false;
        }
    }
    
    private static boolean validateHostname(
        org.bouncycastle.asn1.x509.Certificate cert,
        String expectedHost
    ) {
        try {
            Extensions extensions = cert.getTBSCertificate().getExtensions();
            if (extensions != null) {
                Extension sanExt = extensions.getExtension(Extension.subjectAlternativeName);
                if (sanExt != null) {          
                    try {
                        byte[] extOctets = sanExt.getExtnValue().getOctets();
                        GeneralNames names = GeneralNames.getInstance(extOctets);
                        GeneralName[] nameArray = names.getNames();
                        
                        for (int i = 0; i < nameArray.length; i++) {
                            GeneralName name = nameArray[i];
                            if (name.getTagNo() == GeneralName.dNSName) {
                                String dnsName = DERIA5String.getInstance(name.getName()).getString();
                                if (matchesHostname(dnsName, expectedHost)) {
                                    return true;
                                }
                            }
                        }
                    } catch (Exception ignored) {
                    }
                }
            }
            
            X500Name subject = cert.getSubject();
            String cn = extractCN(subject);
            return cn != null && matchesHostname(cn, expectedHost);
            
        } catch (Exception e) {
            return false;
        }
    }
    
    private static boolean matchesHostname(String certName, String hostname) {
        if (certName == null || hostname == null) {
            return false;
        }
        
        certName = certName.toLowerCase();
        hostname = hostname.toLowerCase();
        
        if (certName.equals(hostname)) {
            return true;
        }
        
        if (certName.startsWith("*.")) {
            String domain = certName.substring(2);
            if (hostname.endsWith("." + domain)) {
                return true;
            }
        }
        
        return false;
    }
    
    private static String extractCN(X500Name name) {
        try {
            RDN[] rdns = name.getRDNs(BCStyle.CN);
            if (rdns != null && rdns.length > 0) {
                return rdns[0].getFirst().getValue().toString();
            }
        } catch (Exception e) {
        }
        
        String nameStr = name.toString();
        int cnIndex = nameStr.indexOf("CN=");
        if (cnIndex == -1) {
            return null;
        }
        
        int startIndex = cnIndex + 3;
        int endIndex = nameStr.indexOf(',', startIndex);
        
        if (endIndex == -1) {
            return nameStr.substring(startIndex);
        } else {
            return nameStr.substring(startIndex, endIndex);
        }
    }
    
    private static boolean isIPAddress(String host) {
        if (host == null || host.length() == 0) {
            return false;
        }

        boolean onlyDigitsAndDots = true;
        for (int i = 0; i < host.length(); i++) {
            char c = host.charAt(i);
            if (c != '.' && (c < '0' || c > '9')) {
                onlyDigitsAndDots = false;
                break;
            }
        }
        
        return onlyDigitsAndDots || host.indexOf(':') != -1;
    }
    
    // utilities

    private static boolean hasUserAgent(String[] headers) {
        if (headers == null) return false;
        for (int i = 0; i < headers.length; i++) {
            String h = headers[i];
            if (h == null) continue;
            int colon = h.indexOf(':');
            String name = (colon == -1) ? h : h.substring(0, colon);
            if (name.trim().equalsIgnoreCase("User-Agent")) {
                return true;
            }
        }
        return false;
    }
    
    private static String buildConnectionString(String host, int port) {
        String connStr = "socket://" + host + ":" + port;
        
        if (networkInterface.equals("wifi")) {
            connStr += ";deviceside=true;interface=wifi";
        }
        
        return connStr;
    }
    
    private static String stripHttpHeaders(String response) {
        int headerEnd = response.indexOf("\r\n\r\n");
        if (headerEnd != -1) {
            response = response.substring(headerEnd + 4);
        } else {
            headerEnd = response.indexOf("\n\n");
            if (headerEnd != -1) {
                response = response.substring(headerEnd + 2);
            }
        }
        
        return response;
    }
    
    private static String decodeChunkedEncoding(String body) throws IOException {
        StringBuffer result = new StringBuffer();
        int pos = 0;
        
        while (pos < body.length()) {
            int crlfPos = body.indexOf("\r\n", pos);
            if (crlfPos == -1) crlfPos = body.indexOf("\n", pos);
            if (crlfPos == -1) break;
            
            String sizeLine = body.substring(pos, crlfPos).trim();
            if (sizeLine.length() == 0) {
                pos = crlfPos + 2;
                continue;
            }
            
            int semiColon = sizeLine.indexOf(';');
            String hex = (semiColon >= 0) ? sizeLine.substring(0, semiColon) : sizeLine;
            hex = hex.trim();
            
            try {
                long chunkSize = Long.parseLong(hex, 16);
                if (chunkSize == 0) break;
                
                pos = crlfPos + (body.charAt(crlfPos) == '\r' ? 2 : 1);
                if (pos + chunkSize <= body.length()) {
                    result.append(body.substring(pos, (int)(pos + chunkSize)));
                    pos += chunkSize;
                    
                    if (pos < body.length() && body.charAt(pos) == '\r') {
                        pos += 2;
                    } else if (pos < body.length() && body.charAt(pos) == '\n') {
                        pos += 1;
                    }
                } else {
                    break;
                }
            } catch (NumberFormatException e) {
                break;
            }
        }
        
        return result.toString();
    }
}