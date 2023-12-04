#ifndef NfcAdapter_h
#define NfcAdapter_h

#include "MFRC522_I2C.h"
#include "NfcTag.h"
#include "Ndef.h"

// Drivers
#include "MifareClassic.h"
#include "MifareUltralight.h"

//#define NDEF_DEBUG 1

class NfcAdapter
{
    public:
        NfcAdapter(MFRC522 * interface) : shield(interface)
        {
            _key = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
        };
        ~NfcAdapter(void) {};
        void begin(bool verbose = true)
        {
            _verbose = verbose;
#ifdef NDEF_USE_SERIAL

            if(_verbose) {
                shield->PICC_DumpToSerial(shield->uid);
            }
#endif
        };

        void begin(const MFRC522::MIFARE_Key & customKey, bool verbose = true)
        {
            _verbose = verbose;
            _key = customKey;
#ifdef NDEF_USE_SERIAL

            if(_verbose) {
                shield->PICC_DumpToSerial(shield->uid);
            }
#endif
        };
        bool tagPresent(); // tagAvailable
        NfcTag read();
        bool write(NdefMessage & ndefMessage);
        // erase tag by writing an empty NDEF record
        bool erase();
        // format a tag as NDEF
        bool format();
        // reset tag back to factory state
        bool clean();
        void haltTag();
    private:
        MFRC522 * shield;
        NfcTag::TagType guessTagType();
        bool _verbose;
        MFRC522::MIFARE_Key _key;
};

#endif
