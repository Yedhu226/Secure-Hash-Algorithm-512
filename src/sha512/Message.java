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

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

/**
 *
 * @author yedhu226
 */
public class Message {

    private byte[] mess;

    public Message(String in) {
        this.mess = in.getBytes();
        this.mess = padMessage(this.mess);
    }

    public byte[] getMess() {
        return mess;
    }

    // Padding and preprocessing
    private byte[] padMessage(byte[] message) {
        int originalLength = message.length;
        long bitLength = originalLength * 8L;

        // Add 1 bit and padding zero bits
        int paddingLength = 128 - (originalLength % 128);
        if (paddingLength < 17) {
            paddingLength += 128;
        }

        byte[] paddedMessage = Arrays.copyOf(message, originalLength + paddingLength);
        paddedMessage[originalLength] = (byte) 0x80; // Append '1' bit
        
        // Append original message length as little-endian 128-bit integer
        ByteBuffer lengthBuffer = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN).putLong(bitLength);
        System.arraycopy(lengthBuffer.array(), 0, paddedMessage, paddedMessage.length - 16, 16);
        
        return paddedMessage;
    }
}

