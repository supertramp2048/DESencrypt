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
            // 3. Xử lý Padding (PKCS5 Standard)
            if (isEncrypt) {
                int paddingLen = 8 - (data.length % 8);
                byte[] paddedData = new byte[data.length + paddingLen];
                System.arraycopy(data, 0, paddedData, 0, data.length);
                for (int i = data.length; i < paddedData.length; i++) {
                    paddedData[i] = (byte) paddingLen;
                }
                data = paddedData;
            }

            // 4. Mã hóa/Giải mã từng block 8-byte
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            for (int i = 0; i < data.length; i += 8) {
                byte[] block = new byte[8];
                System.arraycopy(data, i, block, 0, 8);
                byte[] resultBlock = Main.encrypt_block_byte(block, subkeys);
                outputStream.write(resultBlock);
            }
            
            byte[] resultData = outputStream.toByteArray();

            // Loại bỏ Padding sau khi giải mã
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
                    "Thời gian thực hiện: " + String.format("%.3f", durationMs) + " ms\n" +
                    "Dung lượng file: " + data.length + " bytes");

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