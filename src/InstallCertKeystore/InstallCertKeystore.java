/*
 * Orginal Code from : http://blogs.sun.com/andreas/resource/InstallCert.java
-----------------------------------------------------------------------------
Additional functions added by mirac cicek :
 * - Choose current keystore director.
 * - Select keystore (jsssecacers or cacerts)   
 * - Copy modified store to the selected security directory. 
 * - input keystore passphrase  
 */
package InstallCertKeystore;
/*
 * Copyright 2006 Sun Microsystems, Inc.  All Rights Reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   - Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *   - Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 *   - Neither the name of Sun Microsystems nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
/**
 * Originally from:
 * http://blogs.sun.com/andreas/resource/InstallCert.java
 * Use:
 * java InstallCert hostname
 * Example:
 *% java InstallCert ecc.fedora.redhat.com
 */

import javax.net.ssl.*;
import java.io.*;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Scanner; //

/**
 * Class used to add the server's certificate to the KeyStore
 * with your trusted certificates.
 */
public class InstallCertKeystore {
/*
    TODO : Mirac Cicek
        - Inputlar ayarlanacak (url, jscecacerts mi cacerts mi, ikisi mi, keystore parolası, java yolu için onay h ise yeni giriş)
        - System.getProperty("java.home") ile java yolu belirle 
        - degistirilen keystore dosyaları filestream ile kopyalanacak.
    */
    public static void main(String[] args) throws Exception {
        int keyStoreOption, port;
        Scanner input = new Scanner(System.in);
        String[] host;
        String JavaPath, optionNewJavaPath,javaPathCurrent,javaPath, keyStorePass;
        javaPathCurrent = System.getProperty("java.home");
        System.out.println("Current Java Installation Directory :" + javaPathCurrent);
        System.out.print("Do you want to change Java Directory (y/n) :");
        optionNewJavaPath = input.nextLine();
        if (optionNewJavaPath.equals("y")) {
            System.out.print("Enter new Java Path (Eg: C:\\Program Files\\Java\\jre1.8.0_101)  :");
            javaPath = input.nextLine();
            System.out.println("New Java Path is :" + javaPath);
        }
        else javaPath = System.getProperty("java.home");
        System.out.print("Enter Passphrase for selected keystore leave blank for default['changeit']:");
       keyStorePass = input.nextLine();
       if (keyStorePass.length() < 1 ) keyStorePass = "changeit";
  //     System.out.print(keyStorePass);
        host = new String[1];
        System.out.print("Enter Host for Certificate Export  :");
        host[0] = input.nextLine();
        System.out.print("Enter Connection Port (enter 443 for default port) :");
        port = input.nextInt();
        if (port < 1) port = 443;
        System.out.print("[1] jssecacerts\n[2] cacerts\n Choose the keystore :");
        keyStoreOption = input.nextInt();
       // System.out.print(keyStorePass);
        installCert(host,keyStoreOption,keyStorePass,javaPath,port);
    }
    public static void installCert(String[] args,int keyStoreOption,String keyStorePass,String javaPath, int port) throws Exception {
        String host;
        String keyStoreFile;
        if (keyStoreOption == 1) keyStoreFile = "jssecacerts";
        else keyStoreFile = "cacerts";
   //     int port = 443; //port config
        char[] passphrase;
        if ((args.length == 1) || (args.length == 2)) {
            String[] c = args[0].split(":");
            host = c[0];
//            port = (c.length == 1) ? 443 : Integer.parseInt(c[1]); // Port önceden tanımlı
            String p = (args.length == 1) ? "changeit" : args[1];
//            passphrase = p.toCharArray(); //pass parametreden okunacak
            passphrase = keyStorePass.toCharArray();
            
        } else {
            System.out.println("Usage: java InstallCert <host>[:port] [passphrase]");
            return;
        }

        File file = new File(keyStoreFile);
        if (file.isFile() == false) {
            char SEP = File.separatorChar;
            File dir = new File(javaPath + SEP
                    + "lib" + SEP + "security");
        // parametreden keystore secimi.
            file = new File(dir, keyStoreFile);
        }
        System.out.println("Loading KeyStore " + file + "...");
        InputStream in = new FileInputStream(file);
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(in, passphrase);
        in.close();

        SSLContext context = SSLContext.getInstance("TLS");
        TrustManagerFactory tmf =
                TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(ks);
        X509TrustManager defaultTrustManager = (X509TrustManager) tmf.getTrustManagers()[0];
        SavingTrustManager tm = new SavingTrustManager(defaultTrustManager);
        context.init(null, new TrustManager[]{tm}, null);
        SSLSocketFactory factory = context.getSocketFactory();

        System.out.println("Opening connection to " + host + ":" + port + "...");
        SSLSocket socket = (SSLSocket) factory.createSocket(host, port);
        socket.setSoTimeout(10000);
        try {
            System.out.println("Starting SSL handshake...");
            socket.startHandshake();
            socket.close();
            System.out.println();
            System.out.println("No errors, certificate is already trusted !!!!! ");
        } catch (SSLException e) {
            System.out.println();
            e.printStackTrace(System.out);
        }

        X509Certificate[] chain = tm.chain;
        if (chain == null) {
            System.out.println("Could not obtain server certificate chain");
            return;
        }

        BufferedReader reader =
                new BufferedReader(new InputStreamReader(System.in));

        System.out.println();
        System.out.println("Server sent " + chain.length + " certificate(s):");
        System.out.println();
        MessageDigest sha1 = MessageDigest.getInstance("SHA1");
        MessageDigest md5 = MessageDigest.getInstance("MD5");
        for (int i = 0; i < chain.length; i++) {
            X509Certificate cert = chain[i];
            System.out.println
                    (" " + (i + 1) + " Subject " + cert.getSubjectDN());
            System.out.println("   Issuer  " + cert.getIssuerDN());
            sha1.update(cert.getEncoded());
            System.out.println("   sha1    " + toHexString(sha1.digest()));
            md5.update(cert.getEncoded());
            System.out.println("   md5     " + toHexString(md5.digest()));
            System.out.println();
        }

        System.out.println("Enter certificate to add to trusted keystore or 'q' to quit: [1]");
        String line = reader.readLine().trim();
        int k;
        try {
            k = (line.length() == 0) ? 0 : Integer.parseInt(line) - 1;
        } catch (NumberFormatException e) {
            System.out.println("KeyStore not changed");
            return;
        }

        X509Certificate cert = chain[k];
        String alias = host + "-" + (k + 1);
        ks.setCertificateEntry(alias, cert);

        OutputStream out = new FileOutputStream(keyStoreFile);
        ks.store(out, passphrase);
        out.close();

        System.out.println();
        System.out.println(cert);
        System.out.println();
        System.out.println
                ("Added certificate to keystore "+ keyStoreFile +" using alias '"
                        + alias + "'");
        //MMC
        System.out.println("Starting copy operation ..");
       File source = new File(System.getProperty("user.dir") + "\\" + keyStoreFile);
       File dest = new File(javaPath + "\\lib\\security\\" + keyStoreFile);
       //  File dest = new File("c:\\asd\bsd\\deneme.txt");
       copyFileUsingFileStreams(source, dest);
       System.out.println("Keystore copied succesfully !");
       // *
    }

    private static final char[] HEXDIGITS = "0123456789abcdef".toCharArray();
    // copy File Method
    private static void copyFileUsingFileStreams(File source, File dest) throws IOException {
	InputStream input = null;
	OutputStream output = null;
	    try {
	       input = new FileInputStream(source);
	       output = new FileOutputStream(dest);
               byte[] buf = new byte[1024];
               int bytesRead;
	       while ((bytesRead = input.read(buf)) > 0) {
	          output.write(buf, 0, bytesRead);
	       }
	    } finally {
	       input.close();
	       output.close();
	    }
    }
    
    
    private static String toHexString(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 3);
        for (int b : bytes) {
            b &= 0xff;
            sb.append(HEXDIGITS[b >> 4]);
            sb.append(HEXDIGITS[b & 15]);
            sb.append(' ');
        }
        return sb.toString();
    }

    private static class SavingTrustManager implements X509TrustManager {

        private final X509TrustManager tm;
        private X509Certificate[] chain;

        SavingTrustManager(X509TrustManager tm) {
            this.tm = tm;
        }

        public X509Certificate[] getAcceptedIssuers() {
	   
	    /** 
	     * This change has been done due to the following resolution advised for Java 1.7+
		http://infposs.blogspot.kr/2013/06/installcert-and-java-7.html
       	     **/ 
	    
	    return new X509Certificate[0];	
            //throw new UnsupportedOperationException();
        }

        public void checkClientTrusted(X509Certificate[] chain, String authType)
                throws CertificateException {
            throw new UnsupportedOperationException();
        }

        public void checkServerTrusted(X509Certificate[] chain, String authType)
                throws CertificateException {
            this.chain = chain;
            tm.checkServerTrusted(chain, authType);
        }
    }
}
