/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Main.java to edit this template
 */
package sha512;

import java.util.Scanner;
import static sha512.Digestor.digest;

/**
 *
 * @author yedhu226
 */
public class Main {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        Scanner sc = new Scanner(System.in);
        System.out.print("Enter message: ");
        String m = sc.nextLine();
        System.out.println();
        Message M = new Message(m);
        byte[] res = digest(M);
        System.out.print("Final Digest: ");
        for (byte b : res) {
            System.out.printf("%02x", b);
        }
        System.out.println();
    }
    
}
