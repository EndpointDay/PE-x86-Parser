import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Scanner;

public class Main {

    public static void main(String[] args) {
        try (Scanner scanner = new Scanner(System.in)) {
            System.out.print("Enter the path to the PE file: ");
            String filePath = scanner.nextLine();
            parsePEFile(filePath);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void parsePEFile(String filePath) throws IOException {
        File file = new File(filePath);
        if (!file.exists() || file.isDirectory()) {
            System.out.println("Invalid file path.");
            return;
        }

        try (FileInputStream fis = new FileInputStream(file)) {
            byte[] dosHeader = new byte[64];
            fis.read(dosHeader);

            if (dosHeader[0] == 'M' && dosHeader[1] == 'Z') {
                System.out.println("DOS Signature (MZ) found.");
            } else {
                System.out.println("Not a valid PE file.");
                return;
            }

            int peHeaderOffset = ByteBuffer.wrap(dosHeader, 0x3C, 4).order(ByteOrder.LITTLE_ENDIAN).getInt();
            System.out.println("PE Header Offset: 0x" + Integer.toHexString(peHeaderOffset));

            fis.skip(peHeaderOffset - 64);

            byte[] peHeader = new byte[24];
            fis.read(peHeader);

            if (peHeader[0] == 'P' && peHeader[1] == 'E' && peHeader[2] == 0 && peHeader[3] == 0) {
                System.out.println("PE Signature (PE\\0\\0) found.");
            } else {
                System.out.println("Invalid PE signature.");
                return;
            }

            short machine = ByteBuffer.wrap(peHeader, 4, 2).order(ByteOrder.LITTLE_ENDIAN).getShort();
            System.out.println("Machine: 0x" + Integer.toHexString(machine));

            short numberOfSections = ByteBuffer.wrap(peHeader, 6, 2).order(ByteOrder.LITTLE_ENDIAN).getShort();
            System.out.println("Number of sections: " + numberOfSections);

            int timeDateStamp = ByteBuffer.wrap(peHeader, 8, 4).order(ByteOrder.LITTLE_ENDIAN).getInt();
            System.out.println("Timestamp: 0x" + Integer.toHexString(timeDateStamp));

            short optionalHeaderSize = ByteBuffer.wrap(peHeader, 20, 2).order(ByteOrder.LITTLE_ENDIAN).getShort();
            System.out.println("Optional Header Size: " + optionalHeaderSize);

            parseOptionalHeader(fis, optionalHeaderSize);
            parseSections(fis, numberOfSections, peHeaderOffset + 24 + optionalHeaderSize);
        }
    }

    private static void parseOptionalHeader(FileInputStream fis, short optionalHeaderSize) throws IOException {
        byte[] optionalHeader = new byte[optionalHeaderSize];
        fis.read(optionalHeader);

        int imageBase = ByteBuffer.wrap(optionalHeader, 0x34, 4).order(ByteOrder.LITTLE_ENDIAN).getInt();
        System.out.println("Image Base: 0x" + Integer.toHexString(imageBase));

        int entryPoint = ByteBuffer.wrap(optionalHeader, 0x28, 4).order(ByteOrder.LITTLE_ENDIAN).getInt();
        System.out.println("Entry Point: 0x" + Integer.toHexString(entryPoint));

        int sectionAlignment = ByteBuffer.wrap(optionalHeader, 0x38, 4).order(ByteOrder.LITTLE_ENDIAN).getInt();
        System.out.println("Section Alignment: 0x" + Integer.toHexString(sectionAlignment));

        int fileAlignment = ByteBuffer.wrap(optionalHeader, 0x3C, 4).order(ByteOrder.LITTLE_ENDIAN).getInt();
        System.out.println("File Alignment: 0x" + Integer.toHexString(fileAlignment));

        parseDataDirectories(fis, optionalHeaderSize);
    }

    private static void parseDataDirectories(FileInputStream fis, short optionalHeaderSize) throws IOException {
        byte[] optionalHeader = new byte[optionalHeaderSize];
        fis.read(optionalHeader);

        int exportTableRVA = ByteBuffer.wrap(optionalHeader, 0x60, 4).order(ByteOrder.LITTLE_ENDIAN).getInt();
        int importTableRVA = ByteBuffer.wrap(optionalHeader, 0x64, 4).order(ByteOrder.LITTLE_ENDIAN).getInt();
        int resourceTableRVA = ByteBuffer.wrap(optionalHeader, 0x68, 4).order(ByteOrder.LITTLE_ENDIAN).getInt();
        int exceptionTableRVA = ByteBuffer.wrap(optionalHeader, 0x6C, 4).order(ByteOrder.LITTLE_ENDIAN).getInt();
        int certificateTableRVA = ByteBuffer.wrap(optionalHeader, 0x70, 4).order(ByteOrder.LITTLE_ENDIAN).getInt();
        int baseRelocTableRVA = ByteBuffer.wrap(optionalHeader, 0x74, 4).order(ByteOrder.LITTLE_ENDIAN).getInt();
        int debugTableRVA = ByteBuffer.wrap(optionalHeader, 0x78, 4).order(ByteOrder.LITTLE_ENDIAN).getInt();
        int architectureTableRVA = ByteBuffer.wrap(optionalHeader, 0x7C, 4).order(ByteOrder.LITTLE_ENDIAN).getInt();
        int globalPtrRVA = ByteBuffer.wrap(optionalHeader, 0x80, 4).order(ByteOrder.LITTLE_ENDIAN).getInt();
        int tlsTableRVA = ByteBuffer.wrap(optionalHeader, 0x84, 4).order(ByteOrder.LITTLE_ENDIAN).getInt();
        int loadConfigTableRVA = ByteBuffer.wrap(optionalHeader, 0x88, 4).order(ByteOrder.LITTLE_ENDIAN).getInt();
        int boundImportTableRVA = ByteBuffer.wrap(optionalHeader, 0x8C, 4).order(ByteOrder.LITTLE_ENDIAN).getInt();
        int iatRVA = ByteBuffer.wrap(optionalHeader, 0x90, 4).order(ByteOrder.LITTLE_ENDIAN).getInt();
        int delayImportDescriptorRVA = ByteBuffer.wrap(optionalHeader, 0x94, 4).order(ByteOrder.LITTLE_ENDIAN).getInt();
        int clrRuntimeHeaderRVA = ByteBuffer.wrap(optionalHeader, 0x98, 4).order(ByteOrder.LITTLE_ENDIAN).getInt();
        int reservedRVA = ByteBuffer.wrap(optionalHeader, 0x9C, 4).order(ByteOrder.LITTLE_ENDIAN).getInt();

        System.out.println("Export Table RVA: 0x" + Integer.toHexString(exportTableRVA));
        System.out.println("Import Table RVA: 0x" + Integer.toHexString(importTableRVA));
        System.out.println("Resource Table RVA: 0x" + Integer.toHexString(resourceTableRVA));
        System.out.println("Exception Table RVA: 0x" + Integer.toHexString(exceptionTableRVA));
        System.out.println("Certificate Table RVA: 0x" + Integer.toHexString(certificateTableRVA));
        System.out.println("Base Reloc Table RVA: 0x" + Integer.toHexString(baseRelocTableRVA));
        System.out.println("Debug Table RVA: 0x" + Integer.toHexString(debugTableRVA));
        System.out.println("Architecture Table RVA: 0x" + Integer.toHexString(architectureTableRVA));
        System.out.println("Global Ptr RVA: 0x" + Integer.toHexString(globalPtrRVA));
        System.out.println("TLS Table RVA: 0x" + Integer.toHexString(tlsTableRVA));
        System.out.println("Load Config Table RVA: 0x" + Integer.toHexString(loadConfigTableRVA));
        System.out.println("Bound Import Table RVA: 0x" + Integer.toHexString(boundImportTableRVA));
        System.out.println("IAT RVA: 0x" + Integer.toHexString(iatRVA));
        System.out.println("Delay Import Descriptor RVA: 0x" + Integer.toHexString(delayImportDescriptorRVA));
        System.out.println("CLR Runtime Header RVA: 0x" + Integer.toHexString(clrRuntimeHeaderRVA));
        System.out.println("Reserved RVA: 0x" + Integer.toHexString(reservedRVA));
    }

    private static void parseSections(FileInputStream fis, short numberOfSections, int sectionHeaderOffset) throws IOException {
        fis.getChannel().position(sectionHeaderOffset);

        byte[] sectionHeader = new byte[40];
        for (int i = 0; i < numberOfSections; i++) {
            fis.read(sectionHeader);

            String name = new String(sectionHeader, 0, 8, "ISO-8859-1").trim();

            name = name.replaceAll("[^\\p{Print}]", "?");

            int virtualSize = ByteBuffer.wrap(sectionHeader, 8, 4).order(ByteOrder.LITTLE_ENDIAN).getInt();
            int virtualAddress = ByteBuffer.wrap(sectionHeader, 12, 4).order(ByteOrder.LITTLE_ENDIAN).getInt();
            int sizeOfRawData = ByteBuffer.wrap(sectionHeader, 16, 4).order(ByteOrder.LITTLE_ENDIAN).getInt();
            int pointerToRawData = ByteBuffer.wrap(sectionHeader, 20, 4).order(ByteOrder.LITTLE_ENDIAN).getInt();
            int characteristics = ByteBuffer.wrap(sectionHeader, 36, 4).order(ByteOrder.LITTLE_ENDIAN).getInt();

            System.out.println("Section Name: " + name);
            System.out.println("Virtual Size: 0x" + Integer.toHexString(virtualSize));
            System.out.println("Virtual Address: 0x" + Integer.toHexString(virtualAddress));
            System.out.println("Size of Raw Data: 0x" + Integer.toHexString(sizeOfRawData));
            System.out.println("Pointer to Raw Data: 0x" + Integer.toHexString(pointerToRawData));
            System.out.println("Characteristics: 0x" + Integer.toHexString(characteristics));
            System.out.println();
        }
    }
}
