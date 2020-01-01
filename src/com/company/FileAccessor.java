package com.company;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

public class FileAccessor {

    public FileAccessor(){
        //createDatabase();
    }

    public String get(String studentName){
        String fullFile = "C CASSER FDP !";

        try {

            File file = new File("D:\\SSD_DATABASE\\"+studentName);
            BufferedReader br = new BufferedReader(new FileReader(file));
            fullFile = "";
            String line;
            while ((line = br.readLine()) != null){
                fullFile += line;
            }

        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        return fullFile;
    }

    public String connect( String username , String password){

        boolean A = fileContain("AdminLogins" ,username+":"+password );
        boolean B = fileContain("StudentLogins" ,username+":"+password );
        boolean C = fileContain("TeachersLogins" ,username+":"+password );

        if(A){
            return "ADMIN_"+username;
        }else if(B){
            return "STUDENT_"+username;
        }else if(C){
            return "TEACHER"+username;
        }else{
            return "NOTHING";
        }
    }

    public String set(String teacherName , String studentName , String course , float grade){

        boolean A = fileIntegrity(course);
        boolean D = fileIntegrity(studentName);
        if(A && D){
            boolean B = fileContain(course , teacherName);
            if(B){
                boolean C = fileContain(course , studentName);
                if(C){
                    boolean E = fileContain(studentName , course);
                    if(!E){
                        boolean F = writeFile(studentName,course,grade);
                        if(F){
                            confirmFile(studentName);
                            return " GRADE WAS ENCODED SUCCESSFULLY ! ";
                        }else{
                            return " GRADE WAS NOT ENCODED ! ";
                        }
                    }else{
                        return " STUDENT ALREADY GRADED IN THIS COURSE ! ";
                    }
                }else{
                    return " STUDENT DONT ATTEND THIS COURSE ! ";
                }
            }else{
                return " TEACHER CANNOT GRADE THIS COURSE ! ";
            }
        }else{
            return " FILE INTEGRITY BROKEN ! "+course+" : "+ A + " , "+studentName+" : " + D  ;
        }
    }

    public String adminSet(String studentName , String course , float grade){

        boolean A = fileIntegrity(course);
        boolean D = fileIntegrity(studentName);
        if(A && D){
                boolean C = fileContain(course , studentName);
                if(C){
                        boolean F = writeFile(studentName,course,grade);
                        if(F){
                            confirmFile(studentName);
                            return " GRADE WAS ENCODED SUCCESSFULLY ! ";
                        }else{
                            return " GRADE WAS NOT ENCODED ! ";
                        }
                }else{
                    return " STUDENT DONT ATTEND THIS COURSE ! ";
                }
        }else{
            return " FILE INTEGRITY BROKEN ! "+course+" : "+ A + " , "+studentName+" : " + D  ;
        }
    }

    private void createDatabase(){

        File logins = new File("D:\\SSD_DATABASE\\logins");

        File math = new File("D:\\SSD_DATABASE\\math");
        File french = new File("D:\\SSD_DATABASE\\french");
        File student1 = new File("D:\\SSD_DATABASE\\student1");

        File hash = new File("D:\\SSD_DATABASE\\hash");

        try {
            logins.createNewFile();
            math.createNewFile();
            french.createNewFile();
            student1.createNewFile();
            hash.createNewFile();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private boolean fileContain(String fileName , String name){

        try {

            File file = new File("D:\\SSD_DATABASE\\"+fileName);
            BufferedReader br = new BufferedReader(new FileReader(file));

            String line;
            while ((line = br.readLine()) != null){
                if(line.contains(name))
                    return true;
            }

        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        return false;
    }

    private boolean writeFile(String fileName , String course , float grade){

        if(grade < 0 || grade > 20){
            return false;
        }
        File file = new File("D:\\SSD_DATABASE\\"+fileName);

        List<String> fileContent = null;
        BufferedWriter writer = null;
        try {
            fileContent = new ArrayList<>(Files.readAllLines(file.toPath(), StandardCharsets.UTF_8));

            for (int i = 0; i < fileContent.size(); i++) {
                if (fileContent.get(i).contains(course)) {
                    fileContent.set(i, course+":"+grade);
                    System.out.println("Je suis benjamin=pute");
                    Files.write(file.toPath(), fileContent, StandardCharsets.UTF_8);
                    return true;
                }
            }

            writer = new BufferedWriter(new FileWriter("D:\\SSD_DATABASE\\"+fileName, true));
            String toAppend = "\n"+course+":"+grade;
            writer.append(toAppend);
            writer.close();
            System.out.println("Je suis une pute");
            return true;

        } catch (IOException e) {
            e.printStackTrace();
            return false;
        }

    }

    // File Integrity TODO

    private boolean fileIntegrity(String fileName){

        String hash = getFileHash(fileName);

        return true;
    }

    private void confirmFile(String fileName){


    }

    private String getFileHash(String fileName){

        MessageDigest digest = null;
        try {
            digest = MessageDigest.getInstance("SHA-256");

            // byte[] hash = digest.digest(data.getBytes("UTF-8"));
            //return bytesToHex(hash);

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        return "";
    }

}
