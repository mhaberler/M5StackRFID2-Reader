// RFID URL Writer for M5Stack RFID 2 Unit (WS1850S/MFRC522 I2C) by ksasao
//
// Writes a Tag single URI record (https://m5stack.com/) to an NFC formatted tag. Note this erases all existing records.
// forked from NDEF Library for Arduino by TheNitek https://github.com/TheNitek/NDEF (BSD License)
//             RFID_RC522 by M5Stack https://github.com/m5stack/M5Stack/tree/master/examples/Unit/RFID_RC522 (MIT license)
#include <M5Unified.h>
#include "MFRC522_I2C.h"
#include "NfcAdapter.h"

MFRC522 mfrc522(0x28); // Create MFRC522 instance
char str[256];

NfcAdapter nfc = NfcAdapter(&mfrc522);

MFRC522::MIFARE_Key knownKeys[] = {
    {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, // chinese clone default key
    {0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5}, // A0 A1 A2 A3 A4 A5
    {0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5}, // B0 B1 B2 B3 B4 B5
    {0x4d, 0x3a, 0x99, 0xc3, 0x51, 0xdd}, // 4D 3A 99 C3 51 DD
    {0x1a, 0x98, 0x2c, 0x7e, 0x45, 0x9a}, // 1A 98 2C 7E 45 9A
    {0xd3, 0xf7, 0xd3, 0xf7, 0xd3, 0xf7}, // D3 F7 D3 F7 D3 F7
    {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}, // AA BB CC DD EE FF
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, // 00 00 00 00 00 00
    {0xd3, 0xf7, 0xd3, 0xf7, 0xd3, 0xf7}, // d3 f7 d3 f7 d3 f7
    {0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0}, // a0 b0 c0 d0 e0 f0
    {0xa1, 0xb1, 0xc1, 0xd1, 0xe1, 0xf1}, // a1 b1 c1 d1 e1 f1
    {0x71, 0x4c, 0x5c, 0x88, 0x6e, 0x97}, // 71 4c 5c 88 6e 97
    {0x58, 0x7e, 0xe5, 0xf9, 0x35, 0x0f}, // 58 7e e5 f9 35 0f
    {0xa0, 0x47, 0x8c, 0xc3, 0x90, 0x91}, // a0 47 8c c3 90 91
    {0x53, 0x3c, 0xb6, 0xc7, 0x23, 0xf6}, // 53 3c b6 c7 23 f6
    {0x8f, 0xd0, 0xa4, 0xf2, 0x56, 0xe9}  // 8f d0 a4 f2 56 e9
};

void setup()
{
    delay(3000);
    M5.begin();
    Wire.begin();
    Serial.println("NDEF\nPlace a formatted Mifare Classic or Ultralight NFC tag on the reader.");
    mfrc522.PCD_Init();
    nfc.begin();
    // use a custom Mifare Classic key:
    // nfc.begin(knownKeys[0], true);
}

void loop()
{
    if(nfc.tagPresent()) {
        // Show Nfc Tag type
        byte piccType = mfrc522.PICC_GetType((&mfrc522.uid)->sak);
        Serial.print("PICC type: ");
        Serial.println(mfrc522.PICC_GetTypeName(piccType));

        // have UUID in mfrc522.uid.uidByte, could map to custom keys here
        switch(piccType) {
            case MFRC522::PICC_TYPE_MIFARE_MINI:
            case MFRC522::PICC_TYPE_MIFARE_1K:
            case MFRC522::PICC_TYPE_MIFARE_4K:
                // nfc.setKeys(keya, keyb);
                break;
            default:
                break;
        }

        // Show Uid
        NfcTag tag = nfc.read();

        Serial.print("UID      : ");
        Serial.println(tag.getUidString());
        Serial.println();

        if(tag.hasNdefMessage()) { // every tag won't have a message

            NdefMessage message = tag.getNdefMessage();
            Serial.print("\nThis NFC Tag contains an NDEF Message with ");
            Serial.print(message.getRecordCount());
            Serial.print(" NDEF Record");
            if(message.getRecordCount() != 1) {
                Serial.print("s");
            }
            Serial.println(".");

            // cycle through the records, printing some info from each
            int recordCount = message.getRecordCount();
            for(int i = 0; i < recordCount; i++) {
                Serial.printf("\nNDEF Record %d ", i + 1);
                NdefRecord record = message.getRecord(i);
                // NdefRecord record = message[i]; // alternate syntax

                Serial.print("  TNF: ");
                Serial.print(record.getTnf());
                const byte * type = record.getType();
                unsigned int typeLength = record.getTypeLength();

                // The TNF and Type should be used to determine how your application processes the payload
                // There's no generic processing for the payload, it's returned as a byte[]
                const int payloadLength = record.getPayloadLength();
                const byte * payload = record.getPayload();

                Serial.printf("  Type %d/0x%x,  typelen=%d payloadLen=%d type=", *type, *type, typeLength, payloadLength);
                PrintHexChar(type, typeLength);
                // Print the Hex and Printable Characters
                Serial.print("payload=");
                PrintHexChar(payload, payloadLength);

                // Force the data into a String (might work depending on the content)
                // Real code should use smarter processing
                String payloadAsString = "";
                for(int c = 0; c < payloadLength; c++) {
                    payloadAsString += (char)payload[c];
                }
                Serial.print("payload (as String): ");
                Serial.println(payloadAsString);

                // id is probably blank and will return ""
                const byte * uid = record.getId();
                unsigned int uidLength = record.getIdLength();

                if(uidLength) {
                    Serial.printf("  ID len=%d:\n", uidLength);
                    PrintHexChar(uid, uidLength);
                }
            }
        }
    }
    delay(1000);
}
