#ifndef MifareClassic_h
#define MifareClassic_h

#ifdef NDEF_SUPPORT_MIFARE_CLASSIC

//#define MIFARE_CLASSIC_DEBUG 1

#define BLOCK_SIZE 16
#define LONG_TLV_SIZE 4
#define SHORT_TLV_SIZE 2

#include "Due.h"
#include "MFRC522_I2C.h"
#include "Ndef.h"
#include "NfcTag.h"

class MifareClassic
{
    public:
        MifareClassic(MFRC522 * nfcShield, const MFRC522::MIFARE_Key & key)
            : _nfcShield(nfcShield), _key(key) {};
        ~MifareClassic();
        NfcTag read();
        bool write(NdefMessage & ndefMessage);
        bool formatNDEF();
        bool formatMifare();
    private:
        MFRC522 * _nfcShield;
        int getBufferSize(int messageLength);
        int getNdefStartIndex(byte * data);
        bool decodeTlv(byte * data, int * messageLength, int * messageStartIndex);
        const MFRC522::MIFARE_Key & _key;

};

#endif
#endif
