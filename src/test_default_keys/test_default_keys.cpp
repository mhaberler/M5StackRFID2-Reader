/*
 * ----------------------------------------------------------------------------
 * This is a MFRC522 library example;
 * based on https://github.com/miguelbalboa/rfid
 *
 * NOTE: The library file MFRC522.h has a lot of useful info. Please read it.
 *
 * Released into the public domain.
 * ----------------------------------------------------------------------------
 * Example sketch/program which will try the most used default keys listed in
 * https://code.google.com/p/mfcuk/wiki/MifareClassicDefaultKeys to dump the
 * block 0 of a MIFARE RFID card using a RFID-RC522 reader.
 *
 * Typical pin layout used:
 * -----------------------------------------------------------------------------------------
 *             MFRC522      Arduino       Arduino   Arduino    Arduino          Arduino
 *             Reader/PCD   Uno           Mega      Nano v3    Leonardo/Micro   Pro Micro
 * Signal      Pin          Pin           Pin       Pin        Pin              Pin
 * -----------------------------------------------------------------------------------------
 * RST/Reset   RST          9             5         D9         RESET/ICSP-5     RST
 * SPI SS      SDA(SS)      10            53        D10        10               10
 * SPI MOSI    MOSI         11 / ICSP-4   51        D11        ICSP-4           16
 * SPI MISO    MISO         12 / ICSP-1   50        D12        ICSP-1           14
 * SPI SCK     SCK          13 / ICSP-3   52        D13        ICSP-3           15
 *
 */

#include <M5Unified.h>
#include "MFRC522_I2C.h"

MFRC522 mfrc522(0x28); // Create MFRC522 instance

// Number of known default keys (hard-coded)
// NOTE: Synchronize the NR_KNOWN_KEYS define with the defaultKeys[] array
#define NR_KNOWN_KEYS   16
byte knownKeys[NR_KNOWN_KEYS][MFRC522::MF_KEY_SIZE] =  {
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
    {0x8f, 0xd0, 0xa4, 0xf2, 0x56, 0xe9}, // 8f d0 a4 f2 56 e9
    {0xff, 0xff, 0xff, 0xff, 0xff, 0xff}  // FF FF FF FF FF FF

};

byte uidByte_prev[10] ;

int keyCounter = 0;

/*
 * Initialize.
 */
void setup()
{
    delay(3000);
    auto cfg = M5.config();
    cfg.serial_baudrate = 115200;
    cfg.led_brightness = 128;
    cfg.internal_spk = false;
    cfg.internal_mic = false;
    cfg.internal_imu = true; // enable M5Unified IMU drivers
    cfg.clear_display = true;
    M5.begin(cfg);
    Wire.begin();

    mfrc522.PCD_Init();         // Init MFRC522 card
    // mfrc522.PICC_DumpToSerial();  // Show details of PCD - MFRC522 Card Reader details

    Serial.println(F("Try the most used default keys to print block 0 of a MIFARE Classic 1k."));
}

/*
 * Helper routine to dump a byte array as hex values to Serial.
 */
void dump_byte_array(const byte * buffer, const byte bufferSize)
{
    for(byte i = 0; i < bufferSize; i++) {
        Serial.print(buffer[i] < 0x10 ? " 0" : " ");
        Serial.print(buffer[i], HEX);
    }
}

/*
 * Try using the PICC (the tag/card) with the given key to access block 0.
 * On success, it will show the key details, and dump the block data on Serial.
 *
 * @return true when the given key worked, false otherwise.
 */
boolean try_key(const MFRC522::MIFARE_Key & key)
{
    boolean result = false;
    byte buffer[18];
    byte block = 0;
    MFRC522::StatusCode status;

    //    for (byte j = 0; j < 63; j++) {
    Serial.print(F("  ->  Authenticating using key A...  "));
    status = mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, block, key, mfrc522.uid);
    if(status != MFRC522::STATUS_OK) {
        Serial.print(F("PCD_Authenticate() failed: "));
        Serial.println(mfrc522.GetStatusCodeName(status));
        return false;
    }

    // Read block
    byte byteCount = sizeof(buffer);
    status = mfrc522.MIFARE_Read(block, buffer, &byteCount);
    if(status != MFRC522::STATUS_OK) {
        Serial.print(F("MIFARE_Read() failed: "));
        Serial.println(mfrc522.GetStatusCodeName(status));
    }
    else {
        // Successful read
        result = true;
        Serial.print(F("Success with key:"));
        dump_byte_array(&key.keyByte[0], MFRC522::MF_KEY_SIZE);
        Serial.println();

        // Dump block data
        Serial.print(F("Block "));
        Serial.print(block);
        Serial.print(F(":"));
        dump_byte_array(buffer, 16);
        Serial.println();
    }
    Serial.println();

    //      j++;

    //    }

    mfrc522.PICC_HaltA();       // Halt PICC
    mfrc522.PCD_StopCrypto1();  // Stop encryption on PCD
    return result;
}

/*
 * Main loop.
 */
void loop()
{
    // Look for new cards
    if(! mfrc522.PICC_IsNewCardPresent()) {
        return;
    }

    // Select one of the cards
    if(! mfrc522.PICC_ReadCardSerial())
        return;

    // Print card info just if new!
    if(uidByte_prev[0] != mfrc522.uid.uidByte[0])  {
        keyCounter = 0;

        uidByte_prev[0] = mfrc522.uid.uidByte[0];

        //mfrc522.PICC_DumpToSerial(&(mfrc522.uid));
        Serial.print(F("\n\nCard UID:"));
        dump_byte_array(mfrc522.uid.uidByte, mfrc522.uid.size);

        Serial.println();

        Serial.print(F("PICC type: "));
        MFRC522::PICC_Type piccType = (MFRC522::PICC_Type) mfrc522.PICC_GetType(mfrc522.uid.sak);
        Serial.println(mfrc522.PICC_GetTypeName(piccType));
        Serial.println("\n\n");
    }

    // Try the known default keys
    MFRC522::MIFARE_Key key;

    byte k = keyCounter;
    // Copy the known key into the MIFARE_Key structure
    for(byte i = 0; i < MFRC522::MF_KEY_SIZE; i++) {
        key.keyByte[i] = knownKeys[k][i];
    }

    Serial.print("Trying key: ");
    dump_byte_array((key).keyByte, MFRC522::MF_KEY_SIZE);

    // Try the key
    if(try_key(key)) {
        // Found and reported on the key and block,
        // no need to try other keys for this PICC
        Serial.println("key found!!");
    }
    else {
        delay(1000);                  // 1s
        keyCounter++;
        //Serial.println(keyCounter);
    }

}
