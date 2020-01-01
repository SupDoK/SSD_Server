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

                    String helloClient = (String)iin.readObject();
                    PublicKey ClientPublicKey =  (PublicKey)iin.readObject() ;
                    String signature =  (String)iin.readObject();

                    if(!helloClient.equals("Client Hello")){
                        //TODO
                    }
                    boolean banswer = verify(helloClient , signature , ClientPublicKey);
                    System.out.println(banswer);
                    if(!banswer){
                        //TODO
                    }

                    CertificateFactory fact = CertificateFactory.getInstance("X.509");
                    FileInputStream is = new FileInputStream ("D:\\SSD\\Certificate.pem");
                    X509Certificate cer = (X509Certificate) fact.generateCertificate(is);

                    oout.writeObject(cer);

                    String AESKey = (String)iin.readObject();

                    String Key = AESKey.split(":")[0];
                    String date = AESKey.split(":")[1];

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
                    }

                    System.out.println(Key);

                    String keyPath = "D:\\SSD\\TAMERSSDKey.der";
                    File privKeyFile = new File(keyPath);

                    DataInputStream dis = new DataInputStream(new FileInputStream(privKeyFile));
                    byte[] privKeyBytes = new byte[(int)privKeyFile.length()];
                    dis.read(privKeyBytes);
                    dis.close();

                    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                    PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(privKeyBytes);
                    RSAPrivateKey privKey = (RSAPrivateKey) keyFactory.generatePrivate(privSpec);


                    Cipher cipher2c = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                    cipher2c.init(Cipher.DECRYPT_MODE, privKey);
                    SecretKeySpec secretKey = new SecretKeySpec(cipher2c.doFinal(Base64.getDecoder().decode(Key)), "AES");

                    //Wipe data !
                    cipher2c = null;
                    privSpec = null;
                    keyFactory= null;
                    privKeyBytes = null;
                    privKeyFile = null;
                    //privKey = null;
                    System.gc();


                    //TODO Generate random IV
                    SecureRandom random = new SecureRandom();
                    byte[] ivSpec = new byte[16];
                    random.nextBytes(ivSpec);
                    //System.out.println(new String(ivSpec));


                    String encodedString = encryptData("Hello Server",secretKey,new IvParameterSpec(ivSpec));
                    //Envoie du message chiffré + IV

                    oout.writeObject(ivSpec);
                    oout.writeObject(encodedString);
                    oout.writeObject(sign(encodedString , privKey));

                    System.out.println(encodedString);

                    byte[] ivSpec2 = ( byte[])iin.readObject();

                    String messageFromClient = (String)iin.readObject();
                    System.out.println(messageFromClient);

                    //check if iv is in the cache
                    if(checkIVCache(ivSpec2)){
                        //TODO
                        throw new Exception("REUSED IV KEY");
                    }

                    String decripted = decryptData(messageFromClient,secretKey,new IvParameterSpec(ivSpec2));
                    //stack iv in the cache
                    ivCache[ivGenerated] = ivSpec2;
                    ivGenerated++;

                    System.out.println( decripted);

                    String A = decripted.split(":")[0];
                    String B = decripted.split(":")[1];


                    System.out.println("Je suis "+A+" et mon pwd est : "+B);

                    String status = fa.connect(A,B);

                    if (!status.equals("NOTHING")){

                        oout.writeObject(A+" as good credentials !");
                        nbGenerated = SendMail(A);
                        System.out.println(nbGenerated);

                        boolean bouboul = true;

                        while (bouboul){
                            String code = (String)iin.readObject();
                            System.out.println("CODE RECU : "+code);

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
                        oout.writeObject(A+" does not exist ! ");
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
