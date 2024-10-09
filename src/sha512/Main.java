/*
 * Copyright (C) 2024 yedhu226
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
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
