package com.company;
import java.io.*;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.nio.file.Files;
import java.security.*;

//NETWORK IMPORT
import java.net.ServerSocket;
import java.net.Socket;

//MAIL IMPORT
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.mail.*;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;

import static java.nio.charset.StandardCharsets.UTF_8;

public class SSDServer {

    private int ivGenerated = 0;
    private byte[][] ivCache;


    private FileAccessor fa;

    public SSDServer(){
        fa = new FileAccessor();
        ivCache = new byte[50][];
        try {
            demarrer();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void demarrer() throws IOException {
        ServerSocket ss = new ServerSocket(9000);

        while(true){

            Socket s = ss.accept();
            // ...

            Thread communication2 = new Thread(() -> {
                int upThread =10000;

                try (ObjectOutputStream oout=new ObjectOutputStream(s.getOutputStream());
                     ObjectInputStream iin = new ObjectInputStream(s.getInputStream())) {
                    int nbGenerated;

                    //Receive HELLO CLIENT !
                    //MESSAGE 1
                    String signedHelloClient = (String)iin.readObject();
                    //MESSAGE 2
                    PublicKey ClientPublicKey =  (PublicKey)iin.readObject() ;
                    //String signature =  (String)iin.readObject();
                    String helloClient = signedHelloClient.split(":")[0];
                    String signature = signedHelloClient.split(":")[1];

                    if(!helloClient.equals("Client Hello")){
                        //TODO
                        boolean banswer = verify(helloClient , signature , ClientPublicKey);
                        System.out.println(banswer);
                        if(!banswer){
                            //TODO
                        }
                    }

                    //LOAD certificate !
                    CertificateFactory fact = CertificateFactory.getInstance("X.509");
                    FileInputStream is = new FileInputStream ("D:\\SSD\\Certificate.pem");
                    X509Certificate cer = (X509Certificate) fact.generateCertificate(is);
                    String keyPath = "D:\\SSD\\TAMERSSDKey.der";
                    File privKeyFile = new File(keyPath);

                    //LOAD private key !
                    DataInputStream dis = new DataInputStream(new FileInputStream(privKeyFile));
                    byte[] privKeyBytes = new byte[(int)privKeyFile.length()];
                    dis.read(privKeyBytes);
                    dis.close();

                    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                    PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(privKeyBytes);
                    RSAPrivateKey privKey = (RSAPrivateKey) keyFactory.generatePrivate(privSpec);

                    //Generate AES key !
                    KeyGenerator keyGen = KeyGenerator.getInstance("AES");
                    keyGen.init(256); // for example
                    SecretKey secretKey = keyGen.generateKey();

                    //Encrypt AES key with RSA
                    Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                    cipher.init(Cipher.ENCRYPT_MODE, ClientPublicKey);
                    byte[] crypteedKey = cipher.doFinal(secretKey.getEncoded());

                    String cryptedkeyString = Base64.getEncoder().encodeToString(crypteedKey);

                    //Send certificate
                    //MESSAGE 3
                    oout.writeObject(cer);
                    // Send encrypted key !
                    //MESSAGE 4
                    String message4 = timeMessage(cryptedkeyString);
                    oout.writeObject(message4+"_"+sign(message4, privKey));

                    //Wipe data !
                    //cipher2c = null;
                    privSpec = null;
                    keyFactory= null;
                    privKeyBytes = null;
                    privKeyFile = null;
                    //privKey = null;
                    System.gc();

                    //MESSAGE 6
                    String messageFromClient0 = (String)iin.readObject();
                    String receivedMessage = prepareReceive(messageFromClient0,secretKey,ClientPublicKey);
                    System.out.println(receivedMessage);

                    //Send server secure handshake
                    String messageToSends = prepareSend("Server Secure Handshake",secretKey ,privKey );
                    //MESSAGE 8
                    oout.writeObject(messageToSends);

                    //Receive user credentials
                    //MESSAGE 9
                    String messageFromClient1 = (String)iin.readObject();
                    String receivedMessage1 = prepareReceive(messageFromClient1,secretKey,ClientPublicKey);
                    System.out.println(receivedMessage1);
                    //check if iv is in the cache
                    //if(checkIVCache(ivSpec2)){
                      //  //TODO
                      //  throw new Exception("REUSED IV KEY");
                   // }

                   //stack iv in the cache
                    //ivCache[ivGenerated] = ivSpec2;
                    //ivGenerated++;

                    String A = receivedMessage1.split("-")[0];
                    String B = receivedMessage1.split("-")[1];

                    System.out.println("Je suis "+A+" et mon pwd est : "+B);

                    String status = fa.connect(A,B);

                    if (!status.equals("NOTHING")){

                        //Send connection answer
                        String messageToSends2 = prepareSend(A+" as good credentials !",secretKey ,privKey );
                        //MESSAGE 10
                        oout.writeObject(messageToSends2);

                        nbGenerated = SendMail(A);
                        System.out.println(nbGenerated);

                        boolean bouboul = true;

                        while (bouboul){

                            //Receive user credentials
                            //MESSAGE 11
                            String code = (String)iin.readObject();
                            String code0 = prepareReceive(code,secretKey,ClientPublicKey);
                            System.out.println("CODE RECU : "+code0);

                            if(code.equals(nbGenerated+"")){
                                String sentToken = status+"_"+12345;

                                oout.writeObject("MATCH:"+sentToken);
                                System.out.println("TOKEN = "+sentToken);

                                boolean bulbybool = true;

                                while (bulbybool){

                                    String[] fullAction = ((String)iin.readObject()).split(":");

                                    String token = fullAction[0];
                                    String action = fullAction[1];

                                    System.out.println(action);

                                    if(token.contains("ADMIN") || token.contains("TEACHER")) {
                                        if(action.equals("READ")){

                                            System.out.println(fullAction[2]);
                                            String answer = fa.get(fullAction[2]);
                                            oout.writeObject(answer);

                                        }else if (action.equals("WRITE")){

                                            System.out.println(fullAction[2]);
                                            System.out.println(fullAction[3]);
                                            System.out.println(fullAction[4]);

                                            String answer = fa.adminSet(fullAction[2],fullAction[3],Float.parseFloat(fullAction[4]));
                                            oout.writeObject(answer);

                                        }else if (action.split(":")[0].equals("EXIT")){
                                            bulbybool = false;

                                        }
                                    }else if(token.contains("STUDENT")){

                                        if(action.equals("READ")){
                                            System.out.println(token.split("_")[1]);
                                            String answer = fa.get(token.split("_")[1]);
                                            oout.writeObject(answer);
                                        }else if (action.split(":")[0].equals("EXIT")){
                                            bulbybool = false;
                                        }
                                    }
                                }

                                bouboul= false;

                            }else{

                                System.out.println("Value of time : "+upThread+"");
                                Thread.sleep(upThread);
                                upThread *= 2;

                                oout.writeObject("NOT MATCH");
                            }
                        }

                    }else{
                        //Send connection answer bis
                        String messageToSends2 = prepareSend(A+" does not exist ! ",secretKey ,privKey );
                        //MESSAGE 10bis
                        oout.writeObject(messageToSends2);
                    }

                    oout.flush();

                    iin.close();
                    oout.close();
                    s.close();
                } catch (Exception e) {
                        System.out.println(e.getMessage());
                }
            });

            communication2.setDaemon(true);
            communication2.start();

        }
    }

    private String prepareSend(String data, SecretKey AESKey, PrivateKey privateKey) throws Exception {

        //TODO Generate random IV
        SecureRandom random = new SecureRandom();
        byte[] ivSpec0 =  new byte[16];

        random.nextBytes(ivSpec0);
        String message5 = encryptData(data,AESKey,new IvParameterSpec(ivSpec0));
        String messageToSend = Base64.getEncoder().encodeToString(ivSpec0)+":"+timeMessage(message5);

        return messageToSend+"_"+sign(messageToSend , privateKey);
    }

    private String prepareReceive(String signedEncString, SecretKey AESKey, PublicKey publicKey) throws Exception {

        String encMessage = signedEncString.split("_")[0];
        String signature2 = signedEncString.split("_")[1];

        boolean banswer0 = verify(encMessage , signature2 , publicKey);
        System.out.println(banswer0);
        if(!banswer0){
            //TODO
        }

        //Check date
        boolean ok0 = checkDates(encMessage.split(":")[1] , encMessage.split(":")[2]);
        System.out.println(ok0);
        if(!ok0){
            //TODO
        }

        //Decipher message
        String decryptedMessage = decryptData(encMessage.split(":")[1] , AESKey ,new IvParameterSpec(Base64.getDecoder().decode(encMessage.split(":")[0])));

        return decryptedMessage;
    }

    private boolean checkDates(String Key , String date){

        System.out.println(date);
        System.out.println(Key);

        //DateFormat df = new SimpleDateFormat("yyyy-MM-dd-hh-mm-ss");

        String[] splitted = date.split("-");

        Calendar construct = Calendar.getInstance();

        construct.set(Calendar.YEAR , Integer.parseInt(splitted[0]));
        construct.set(Calendar.MONTH , Integer.parseInt(splitted[1]));
        construct.set(Calendar.DAY_OF_MONTH , Integer.parseInt(splitted[2]));

        construct.set(Calendar.HOUR , Integer.parseInt(splitted[3]));
        construct.set(Calendar.MINUTE , Integer.parseInt(splitted[4]));
        construct.set(Calendar.SECOND , Integer.parseInt(splitted[5]));

        construct.add(Calendar.SECOND, 360);
        Date toCompareplus5 = construct.getTime();
        Date currentDate = new Date();

        System.out.println(currentDate);
        System.out.println(toCompareplus5);

        if(toCompareplus5.after(currentDate)){
            //TODO
            System.out.println("C OK BOUBOUL");
            return true;
        }

        return false;
    }

    private String timeMessage(String message){
        DateFormat df = new SimpleDateFormat("yyyy-MM-dd-hh-mm-ss");
        Date currentDate = new Date();
        return message+":"+df.format(currentDate);
    }

    private boolean checkIVCache(byte[] toCheckIV){
        for (byte[] iv:ivCache) {
            if(toCheckIV == iv)
                return true;
        }
        return false;
    }

    //Based on https://www.developpez.net/forums/d1803792/java/general-java/signature-verification-rsa-java/
    private static boolean verify(String plainText, String signature, PublicKey publicKey) throws Exception {
        Signature publicSignature = Signature.getInstance("SHA256withRSA");
        publicSignature.initVerify(publicKey);
        publicSignature.update(plainText.getBytes(UTF_8));

        byte[] signatureBytes = Base64.getDecoder().decode(signature);

        return publicSignature.verify(signatureBytes);
    }
    //Based on https://www.developpez.net/forums/d1803792/java/general-java/signature-verification-rsa-java/
    public static String sign(String plainText, PrivateKey privateKey) throws Exception {

        Signature privateSignature = Signature.getInstance("SHA256withRSA");
        privateSignature.initSign(privateKey);
        privateSignature.update(plainText.getBytes(UTF_8));

        byte[] signature = privateSignature.sign();

        return Base64.getEncoder().encodeToString(signature);
    }

    private String encryptData(String data , SecretKey secretKey, IvParameterSpec iv ) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

        Cipher cipherAlpha = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        cipherAlpha.init(Cipher.ENCRYPT_MODE, secretKey, iv);

        byte[] encryptedWithAES = cipherAlpha.doFinal(data.getBytes());

        return Base64.getEncoder().encodeToString(encryptedWithAES);
    }

    private String decryptData(String encData ,SecretKey secretKey, IvParameterSpec iv ) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

        Cipher cipherBeta = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        cipherBeta.init(Cipher.DECRYPT_MODE, secretKey ,iv);
        byte[] original = cipherBeta.doFinal(Base64.getDecoder().decode(encData));

        return new String(original);
    }

    private int SendMail(String mail){
        final String username = "alphatangototo789@gmail.com";
        final String password = "HI2LlOvoTCe2VcZtRqQD";

        SecureRandom rand = new SecureRandom(); //CREATE SECRET MDP TO SEND TO MAIL
        int tempSecret = rand.nextInt(100000);//Generation d'un entier entre 0 et 99999

        Properties prop = new Properties();
        prop.put("mail.smtp.host", "smtp.gmail.com");
        prop.put("mail.smtp.port", "587");
        prop.put("mail.smtp.auth", "true");
        prop.put("mail.smtp.starttls.enable", "true"); //TLS

        Session session = Session.getInstance(prop,
                new javax.mail.Authenticator() {
                    protected PasswordAuthentication getPasswordAuthentication() {//Sender account
                        return new PasswordAuthentication(username, password);
                    }
                });

        try {

            Message message = new MimeMessage(session);
            message.setFrom(new InternetAddress("alphatangototo789@gmail.com"));
            message.setRecipients(
                    Message.RecipientType.TO,
                    //InternetAddress.parse("bencochez86@gmail.com, alphatangototo789@gmail.com")//Destination mails (with a copy to sender)
                    InternetAddress.parse(mail + ", alphatangototo789@gmail.com")
            );
            message.setSubject("Verification of SUPER SSD application");
            message.setText("Your code is," + "\n\n " + tempSecret);

            Transport.send(message);

            System.out.println("Code is send");

        } catch (MessagingException e) {
            e.printStackTrace();
        }
        return tempSecret;
    }

}
