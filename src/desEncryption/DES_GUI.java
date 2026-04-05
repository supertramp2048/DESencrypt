package desEncryption;

import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.util.ArrayList;
import java.util.Collections;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;

public class DES_GUI extends JFrame {

    private JTextField keyField;
    private JTextField fileField;
    private JComboBox<String> modeBox;
    private static final String[] WEAK_KEYS = {
            "0101010101010101",
            "FEFEFEFEFEFEFEFE",
            "E0E0E0E0F1F1F1F1",
            "1F1F1F1F0E0E0E0E"
        };
    private static final String[] SEMI_WEAK_KEYS = {
            "011F011F010E010E", "1F011F010E010E01",
            "01E001E001F101F1", "E001E001F101F101",
            "01FE01FE01FE01FE", "FE01FE01FE01FE01",
            "1FE01FE00EF10EF1", "E01FE01FF10EF10E",
            "1FFE1FFE0EFE0EFE", "FE1FFE1FFE0EFE0E",
            "E0FEE0FEF1FEF1FE", "FEE0FEE0FEF1FEF1"
        };
    private String normalizeKey(String key) {
        return key.replaceAll("\\s+", "").toUpperCase();
    }

    private boolean isWeakKey(String key) {
        key = normalizeKey(key);
        for (String wk : WEAK_KEYS) {
            if (wk.equals(key)) return true;
        }
        return false;
    }

    private boolean isSemiWeakKey(String key) {
        key = normalizeKey(key);
        for (String swk : SEMI_WEAK_KEYS) {
            if (swk.equals(key)) return true;
        }
        return false;
    }
    public DES_GUI() {

        setTitle("DES Encryption Tool");
        setSize(500,250);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null);

        JPanel panel = new JPanel();
        panel.setLayout(new GridLayout(4,2,10,10));

        // Mode
        panel.add(new JLabel("Mode:"));
        modeBox = new JComboBox<>(new String[]{"Mã hóa","Giải mã"});
        panel.add(modeBox);

        // Key
        panel.add(new JLabel("Khóa (HEX):"));
        keyField = new JTextField();
        panel.add(keyField);

        // File
        panel.add(new JLabel("File:"));
        fileField = new JTextField();
        JButton browse = new JButton("Browse");

        browse.addActionListener(e -> chooseFile());

        JPanel filePanel = new JPanel(new BorderLayout());
        filePanel.add(fileField,BorderLayout.CENTER);
        filePanel.add(browse,BorderLayout.EAST);

        panel.add(filePanel);

        // Run button
        JButton runButton = new JButton("Chạy");
        runButton.addActionListener(e -> runDES());

        panel.add(new JLabel());
        panel.add(runButton);

        add(panel);
    }

    private void chooseFile() {
        JFileChooser chooser = new JFileChooser();
        int result = chooser.showOpenDialog(this);

        if(result == JFileChooser.APPROVE_OPTION) {
            fileField.setText(chooser.getSelectedFile().getAbsolutePath());
        }
    }

    
    
    private void runDES() {
        try {
            String key_hex = keyField.getText().trim();
            
            if (key_hex.isEmpty()) {
                JOptionPane.showMessageDialog(this, "Vui lòng nhập khóa HEX!");
                return;
            }
            if (key_hex.length() > 16) {
                JOptionPane.showMessageDialog(this, "Khóa quá dài! DES chỉ hỗ trợ tối đa 16 ký tự HEX (64-bit).\nVui lòng nhập lại.");
                return;
            }
            if (!key_hex.matches("^[0-9A-Fa-f]+$")) {
                JOptionPane.showMessageDialog(this, "Khóa chứa ký tự không hợp lệ! Chỉ chấp nhận từ 0-9 và A-F.");
                return;
            }
         // Check weak key
            String normalizedKey = normalizeKey(key_hex);

            if (isWeakKey(normalizedKey)) {
                JOptionPane.showMessageDialog(this,
                    "Khóa yếu (WEAK KEY) \n" +
                    "Khóa này không an toàn, vui lòng chọn khóa khác!");
                return;
            }

            if (isSemiWeakKey(normalizedKey)) {
                int choice = JOptionPane.showConfirmDialog(this,
                    "Khóa bán yếu (SEMI-WEAK KEY) \n" +
                    "Khóa này có thể gây rủi ro.\n" +
                    "Bạn có muốn tiếp tục không?",
                    "Cảnh báo bảo mật",
                    JOptionPane.YES_NO_OPTION);

                if (choice != JOptionPane.YES_OPTION) {
                    return;
                }
            }
            File inputFile = new File(fileField.getText().trim());
            String mode = (String) modeBox.getSelectedItem();
            boolean isEncrypt = mode.equals("Mã hóa");

            String key_bin = Main.hex_to_bin(key_hex.toUpperCase());
            key_bin = Main.apply_PC1(key_bin);
            ArrayList<String> subkeys = Main.generate_subkeys(key_bin);
            if (!isEncrypt) Collections.reverse(subkeys);

            // Doc File duoi dang mang byte
            byte[] data = Files.readAllBytes(inputFile.toPath());
            long startTime = System.nanoTime();
            //  Them padding
            if (isEncrypt) {
                int paddingLen = 8 - (data.length % 8);
                byte[] paddedData = new byte[data.length + paddingLen];
                System.arraycopy(data, 0, paddedData, 0, data.length);
                for (int i = data.length; i < paddedData.length; i++) {
                    paddedData[i] = (byte) paddingLen;
                }
                data = paddedData;
            }

            // Ma hoa hoac giai ma
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            for (int i = 0; i < data.length; i += 8) {
                byte[] block = new byte[8];
                System.arraycopy(data, i, block, 0, 8);
                byte[] resultBlock = Main.encrypt_block_byte(block, subkeys);
                outputStream.write(resultBlock);
            }
            
            byte[] resultData = outputStream.toByteArray();

            // Bo padding sau giai ma
            if (!isEncrypt) {
                int paddingLen = resultData[resultData.length - 1] & 0xFF;
                if (paddingLen > 0 && paddingLen <= 8) {
                    byte[] unpaddedData = new byte[resultData.length - paddingLen];
                    System.arraycopy(resultData, 0, unpaddedData, 0, unpaddedData.length);
                    resultData = unpaddedData;
                }
            }
            long endTime = System.nanoTime();
            double durationMs = (endTime - startTime) / 1_000_000.0;
            //  Ghi file output 
            String outputName = isEncrypt ? "encrypted_" + inputFile.getName() : "decrypted_" + inputFile.getName();
            Files.write(Paths.get(inputFile.getParent(), outputName), resultData);
            
            String action = isEncrypt ? "Mã hóa" : "Giải mã";
            JOptionPane.showMessageDialog(this, 
                    action + " thành công!\n" +
                    "Thời gian thực hiện: " + String.format("%.3f", durationMs) + " ms");

        } catch (Exception ex) {
            ex.printStackTrace();
            JOptionPane.showMessageDialog(this, "Lỗi: " + ex.getMessage());
        }
    }

    public static void main(String[] args) {

        SwingUtilities.invokeLater(() -> {
            new DES_GUI().setVisible(true);
        });

    }
}