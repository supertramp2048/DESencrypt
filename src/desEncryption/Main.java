package desEncryption;
import java.awt.Choice;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;

public class Main {

    // IP
    static final int[] IP = {
        58, 50, 42, 34, 26, 18, 10, 2,
        60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6,
        64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17,  9, 1,
        59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5,
        63, 55, 47, 39, 31, 23, 15, 7
    };

    // IP^(-1)
    static final int[] IIP = {
        40,  8, 48, 16, 56, 24, 64, 32,
        39,  7, 47, 15, 55, 23, 63, 31,
        38,  6, 46, 14, 54, 22, 62, 30,
        37,  5, 45, 13, 53, 21, 61, 29,
        36,  4, 44, 12, 52, 20, 60, 28,
        35,  3, 43, 11, 51, 19, 59, 27,
        34,  2, 42, 10, 50, 18, 58, 26,
        33,  1, 41,  9, 49, 17, 57, 25
    };

    // (E) bang mo rong hoan vi
    static final int[] EP = {
        32,  1,  2,  3,  4,  5,
         4,  5,  6,  7,  8,  9,
         8,  9, 10, 11, 12, 13,
        12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21,
        20, 21, 22, 23, 24, 25,
        24, 25, 26, 27, 28, 29,
        28, 29, 30, 31, 32,  1
    };

    // Permutation Function (P)
    static final int[] P = {
        16,  7, 20, 21, 29, 12, 28, 17,
         1, 15, 23, 26,  5, 18, 31, 10,
         2,  8, 24, 14, 32, 27,  3,  9,
        19, 13, 30,  6, 22, 11,  4, 25
    };

    // S-box Table
    static int[][][] s_box = {
        {
            {14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7},
            {0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8},
            {4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0},
            {15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13}
        },
        {
            {15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10},
            {3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5},
            {0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15},
            {13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9}
        },
        {
            {10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8},
            {13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1},
            {13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7},
            {1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12}
        },
        {
            {7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15},
            {13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9},
            {10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4},
            {3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14}
        },
        {
            {2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9},
            {14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6},
            {4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14},
            {11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3}
        },
        {
            {12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11},
            {10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8},
            {9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6},
            {4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13}
        },
        {
            {4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1},
            {13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6},
            {1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2},
            {6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12}
        },
        {
            {13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7},
            {1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2},
            {7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8},
            {2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11}
        }
    };

    // bang so bit dich trai cua khoa tuong ung moi vong
    static final int[] shift_table = {
        1, 1, 2, 2,
        2, 2, 2, 2,
        1, 2, 2, 2,
        2, 2, 2, 1
    };
    // trat tu khoa
    static final int[] PC_1 = {
        57, 49, 41, 33, 25, 17,  9,
         1, 58, 50, 42, 34, 26, 18,
        10,  2, 59, 51, 43, 35, 27,
        19, 11,  3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15,
         7, 62, 54, 46, 38, 30, 22,
        14,  6, 61, 53, 45, 37, 29,
        21, 13,  5, 28, 20, 12,  4
    };
    // trat tu nen
    static final int[] PC_2 = {
        14, 17, 11, 24,  1,  5,
         3, 28, 15,  6, 21, 10,
        23, 19, 12,  4, 26,  8,
        16,  7, 27, 20, 13,  2,
        41, 52, 31, 37, 47, 55,
        30, 40, 51, 45, 33, 48,
        44, 49, 39, 56, 34, 53,
        46, 42, 50, 36, 29, 32
    };

   
    static String apply_s_box(String bit_stream) {
        assert bit_stream.length() == 48;
        String new_text = "", text_segment, row_val, left, right, col_val = "";
        int select_box, selected_val, row_val_dec, col_val_dec = 0;
        for (int i = 0; i < 48; i += 6) {
            left = bit_stream.substring(i, i + 1);
            right = bit_stream.substring(i + 5, i + 6);
            row_val = left + right;
            row_val_dec = Integer.parseInt(bin_to_dec(row_val));
            col_val = bit_stream.substring(i + 1, i + 5);
            col_val_dec = Integer.parseInt(bin_to_dec(col_val));
            select_box = i / 6;
            selected_val = s_box[select_box][row_val_dec][col_val_dec];
            text_segment = dec_to_bin(Integer.toString(selected_val));
            new_text += text_segment;
        }
        return new_text;
    }

    
    static String apply_P(String bit_stream) {
        String new_text = "";
        for (int i = 0; i < 32; i++)
            new_text += bit_stream.charAt(P[i] - 1);
        return new_text;
    }

    
    static String apply_IP(String plaintext) {
        String new_text = "";
        for (int i = 0; i < 64; i++) {
            new_text += plaintext.charAt(IP[i] - 1);
        }
        return new_text;
    }

    
    static String apply_IIP(String bit_stream) {
        String new_text = "";
        for (int i = 0; i < 64; i++)
            new_text += bit_stream.charAt(IIP[i] - 1);
        return new_text;
    }

    
    static String apply_EP(String right) {
        String new_text = "";
        for (int i = 0; i < 48; i++) {
            new_text += right.charAt(EP[i] - 1);
        }
        return new_text;
    }

    
    static String apply_PC1(String key) {
        String new_key = "";
        for (int i = 0; i < 56; i++) {
            new_key += key.charAt(PC_1[i] - 1);
        }
        return new_key;
    }

    
    static ArrayList<String> generate_subkeys(String key) {
        ArrayList<String> subkeys = new ArrayList<>();
        String left = "", right = "", newLeft, newRight, temp_key = "", new_key = "";
        for (int i = 0; i < 16; i++) {
            if (i == 0) {
                left = key.substring(0, 28);
                right = key.substring(28, 56);
            } else {
                left = temp_key.substring(0, 28);
                right = temp_key.substring(28, 56);
            }
            if (shift_table[i] == 1) {
                newLeft = left.substring(1, 28) + left.substring(0, 1);
                newRight = right.substring(1, 28) + right.substring(0, 1);
            } else {
                newLeft = left.substring(2, 28) + left.substring(0, 2);
                newRight = right.substring(2, 28) + right.substring(0, 2);
            }
            temp_key = newLeft + newRight;
            new_key = "";
            for (int j = 0; j < 48; j++) {
                new_key += temp_key.charAt(PC_2[j] - 1);
            }
            subkeys.add(new_key);
        }
        return subkeys;
    }
   
    static String round_function(String left32, String right32, ArrayList<String> subkeys) {
        String EP_val, EP_XOR_K, s_box_val, permute, left = "", previousLeft, right = "", encrypted = "";
        for (int i = 0; i < subkeys.size(); i++) {
            if (i == 0) {
                left = left32;
                right = right32;
            }
            EP_val = apply_EP(right);
            EP_XOR_K = XOR(EP_val, subkeys.get(i));
            s_box_val = apply_s_box(EP_XOR_K);
            permute = apply_P(s_box_val);
            previousLeft = left;
            left = right;
            right = XOR(previousLeft, permute);
        }
        encrypted = left + right;
        return encrypted;
    }

    
    static String hex_to_bin(String hex) {
        assert hex.length() <= 16;
        String bin = "";
        HashMap<Character, String> mp = new HashMap<>();
        mp.put('0', "0000");
        mp.put('1', "0001");
        mp.put('2', "0010");
        mp.put('3', "0011");
        mp.put('4', "0100");
        mp.put('5', "0101");
        mp.put('6', "0110");
        mp.put('7', "0111");
        mp.put('8', "1000");
        mp.put('9', "1001");
        mp.put('A', "1010");
        mp.put('B', "1011");
        mp.put('C', "1100");
        mp.put('D', "1101");
        mp.put('E', "1110");
        mp.put('F', "1111");
        for (int i = 0; i < hex.length(); i++) {
            bin += mp.get(hex.charAt(i));
        }
        int zeros_to_prepend = 64 - bin.length();
        for (int i = 0; i < zeros_to_prepend; i++) {
            bin = "0" + bin;
        }
        return bin;
    }

    
    static String bin_to_hex(String bin) {
        assert bin.length() == 64;
        String hex = "";
        HashMap<String, String> mp = new HashMap<>();
        mp.put("0000", "0");
        mp.put("0001", "1");
        mp.put("0010", "2");
        mp.put("0011", "3");
        mp.put("0100", "4");
        mp.put("0101", "5");
        mp.put("0110", "6");
        mp.put("0111", "7");
        mp.put("1000", "8");
        mp.put("1001", "9");
        mp.put("1010", "A");
        mp.put("1011", "B");
        mp.put("1100", "C");
        mp.put("1101", "D");
        mp.put("1110", "E");
        mp.put("1111", "F");
        for (int i = 0; i < bin.length(); i += 4) {
            String ch = "";
            ch += bin.charAt(i);
            ch += bin.charAt(i + 1);
            ch += bin.charAt(i + 2);
            ch += bin.charAt(i + 3);
            hex += mp.get(ch);
        }
        return hex;
    }

    
    static String bin_to_dec(String bin) {
        String dec = "";
        HashMap<String, String> mp = new HashMap<>();
        // for outer bits 1 & 6 (row bits)
        mp.put("00", "0");
        mp.put("01", "1");
        mp.put("10", "2");
        mp.put("11", "3");
        // for inner bits 2-5 (col bits)
        mp.put("0000", "0");
        mp.put("0001", "1");
        mp.put("0010", "2");
        mp.put("0011", "3");
        mp.put("0100", "4");
        mp.put("0101", "5");
        mp.put("0110", "6");
        mp.put("0111", "7");
        mp.put("1000", "8");
        mp.put("1001", "9");
        mp.put("1010", "10");
        mp.put("1011", "11");
        mp.put("1100", "12");
        mp.put("1101", "13");
        mp.put("1110", "14");
        mp.put("1111", "15");
        dec = mp.get(bin);
        return dec;
    }

    
    static String dec_to_bin(String dec) {
        String bin = "";
        HashMap<String, String> mp = new HashMap<>();
        mp.put("0",  "0000");
        mp.put("1",  "0001");
        mp.put("2",  "0010");
        mp.put("3",  "0011");
        mp.put("4",  "0100");
        mp.put("5",  "0101");
        mp.put("6",  "0110");
        mp.put("7",  "0111");
        mp.put("8",  "1000");
        mp.put("9",  "1001");
        mp.put("10", "1010");
        mp.put("11", "1011");
        mp.put("12", "1100");
        mp.put("13", "1101");
        mp.put("14", "1110");
        mp.put("15", "1111");
        bin = mp.get(dec);
        return bin;
    }

    static String XOR(String s1, String s2) {
        assert s1.length() == s2.length();
        String new_string = "";
        for (int i = 0; i < s1.length(); i++) {
            if (s1.charAt(i) == s2.charAt(i))
                new_string += "0";
            else
                new_string += "1";
        }
        return new_string;
    }

 // chuyen mang 8 byte thanh chuoi 64 bit
    static String bytes_to_bin(byte[] bytes) {
        StringBuilder bin = new StringBuilder();
        for (byte b : bytes) {
            String s = Integer.toBinaryString(b & 0xFF);
            while (s.length() < 8) s = "0" + s;
            bin.append(s);
        }
        return bin.toString();
    }

    // chuyen chuoi 64bit to bytes
    static byte[] bin_to_bytes(String bin) {
        byte[] bytes = new byte[8];
        for (int i = 0; i < 8; i++) {
            String byteString = bin.substring(i * 8, (i + 1) * 8);
            bytes[i] = (byte) Integer.parseInt(byteString, 2);
        }
        return bytes;
    }

    // ma hoa 1 block 8 byte
    static byte[] encrypt_block_byte(byte[] block_8bytes, ArrayList<String> subkeys) {
        String bin = bytes_to_bin(block_8bytes);
        bin = apply_IP(bin);
        
        String left = bin.substring(0, 32);
        String right = bin.substring(32, 64);
        String round_result = round_function(left, right, subkeys);
        // Swap L and R
        String encrypted_bin = round_result.substring(32, 64) + round_result.substring(0, 32);
        encrypted_bin = apply_IIP(encrypted_bin);
        return bin_to_bytes(encrypted_bin);
    }
    
   
}

