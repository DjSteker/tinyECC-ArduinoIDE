// **********************************************************************************
// Author: Shubham Annigeri	github.com/ShubhamAnnigeri
// co-Author: Sunit Raut   	github.com/SunitRaut
// co-Author: DjSteker   	github.com/DjSteker
// **********************************************************************************
// License
// **********************************************************************************
// This program is free software; you can redistribute it 
// and/or modify it under the terms of the GNU General    
// Public License as published by the Free Software       
// Foundation; either version 3 of the License, or        
// (at your option) any later version.                    
//                                                        
// This program is distributed in the hope that it will   
// be useful, but WITHOUT ANY WARRANTY; without even the  
// implied warranty of MERCHANTABILITY or FITNESS FOR A   
// PARTICULAR PURPOSE. See the GNU General Public        
// License for more details.                              
//                                                        
// Licence can be viewed at                               
// http://www.gnu.org/licenses/gpl-3.0.txt
//
// Please maintain this license information along with authorship
// and copyright notices in any redistribution of this code
// **********************************************************************************



#include <tinyECC.h>

/* Tabla estática de mapeo */
static const int alpha_table[MAPPING_TABLE_SIZE] = MAPPING_TABLE_DATA;

const int* tinyECC::alphaTable() {
    return alpha_table;
}

int tinyECC::alphaAt(int index) {
#if defined(ARDUINO_ARCH_AVR) || defined(__AVR__)
    return pgm_read_word(&alpha_table[index]);
#else
    return alpha_table[index];
#endif
}

/* ==================== Constructor ==================== */
tinyECC::tinyECC() {
    a = 1;
    b = 23;
    p = 991;

    PubKey[0]   = 775;  PubKey[1]   = 553;
    Pbase[0]    = 1;    Pbase[1]    = 5;
    PrivKey      = 12;
    TempArr[0]  = 0;    TempArr[1]  = 0;
    PubSer[0]   = 775;  PubSer[1]   = 553;
    PbaseSer[0] = 1;    PbaseSer[1] = 5;

    Sig[0] = 0;
    Sig[1] = 0;

    for (int i = 0; i < 4; i++) {
        E[i] = 0;
        P[i] = 0;
    }

    m = 0;
    eccSrand();
}

void tinyECC::eccSrand() {
#ifdef ARDUINO
    randomSeed(analogRead(A0));
#else
    std::srand(static_cast<unsigned>(time(nullptr)));
#endif
}

void tinyECC::setCurve(int aVal, int bVal, int pVal) {
    a = aVal;
    b = bVal;
    p = pVal;
}

void tinyECC::setKeys(int privKey, int pubX, int pubY,
                      int baseX, int baseY) {
    PrivKey    = privKey;
    PubKey[0]  = pubX;   PubKey[1]  = pubY;
    Pbase[0]   = baseX;  Pbase[1]   = baseY;
    PubSer[0]  = pubX;   PubSer[1]  = pubY;
    PbaseSer[0]= baseX;  PbaseSer[1]= baseY;
}

/* ==================== Encrypt ==================== */
void tinyECC::encrypt() {
    ciphertext = "";
    m = 0;

    unsigned int len = plaintext.length();
    for (unsigned int i = 0; i < len; i++) {
        uint8_t x = static_cast<uint8_t>(plaintext[i]);

        if (MAPPING_TABLE_SIZE == 20) {   /* tabla de dígitos 0-9 */
            x = static_cast<uint8_t>(plaintext[i] - '0');
        }

        m = (m + x) % 50;

        int Pm[2];
        Pm[0] = alphaAt(2 * x);
        Pm[1] = alphaAt(2 * x + 1);

        encode(Pm, PubKey, Pbase);

#ifdef ARDUINO
        ciphertext += String(E[0]) + "," + String(E[1]) + ","
                    + String(E[2]) + "," + String(E[3]) + ",";
#else
        ciphertext += std::to_string(E[0]) + "," + std::to_string(E[1]) + ","
                    + std::to_string(E[2]) + "," + std::to_string(E[3]) + ",";
#endif
    }
    m = m % 50;
}

/* ==================== Decrypt ==================== */
void tinyECC::decrypt() {
    int valores[4];
    int idx = 0;
    unsigned int k = 0;
    m = 0;
    plaintext = "";

    while (k < ciphertext.length()) {
        int val = 0;
        bool gotNum = false;

        while (k < ciphertext.length()) {
            char c = ciphertext[k];
            if (c == ',') {
                k++;
                break;
            }
            if (c == '-') {
                /* manejar negativos (no debería ocurrir pero por seguridad) */
                k++;
                continue;
            }
            if (c >= '0' && c <= '9') {
                val = val * 10 + (c - '0');
                gotNum = true;
            }
            k++;
        }

        if (!gotNum) {
            continue;
        }

        valores[idx % 4] = val;
        if ((idx % 4) == 3) {
            P[0] = valores[0];
            P[1] = valores[1];
            P[2] = valores[2];
            P[3] = valores[3];

            decode();  /* resultado en E[0], E[1] */

            /* Buscar punto en la tabla */
            bool found = false;
            int half = MAPPING_TABLE_SIZE / 2;
            for (int j = 0; j < half; j++) {
                if (alphaAt(2 * j) == E[0] && alphaAt(2 * j + 1) == E[1]) {
                    m = (m + j) % 50;
                    if (MAPPING_TABLE_SIZE == 20) {
                        plaintext += static_cast<char>(j + '0');
                    } else {
                        plaintext += static_cast<char>(j);
                    }
                    found = true;
                    break;
                }
            }

            if (!found) {
                /* Caracter no encontrado en la tabla */
#ifdef ARDUINO
                plaintext += '?';
#else
                plaintext += '?';
#endif
            }
        }
        idx++;
    }
    m = m % 50;
}

/* ==================== Encode ==================== */
void tinyECC::encode(int msg[2], int pb[2], int pbase[2]) {
    do {
        E[0] = 0;
        E[1] = 0;
        E[2] = 0;
        E[3] = 0;

        int temp1[2];
        int k = 0;
#ifdef ARDUINO
        k = random(50);
#else
        k = rand() % 50;
#endif

        TempArr[0] = PubKey[0];
        TempArr[1] = PubKey[1];
        sclr_mult(k, TempArr);
        temp1[0] = E[0];
        temp1[1] = E[1];

        add(msg, temp1);
        E[2] = E[0];   /* C2 = msg + k*PubKey */
        E[3] = E[1];

        TempArr[0] = Pbase[0];
        TempArr[1] = Pbase[1];
        sclr_mult(k, TempArr);
        /* E[0],E[1] ya tienen C1 = k*Pbase */

    } while ((E[0] == 0) || (E[1] == 0) || (E[2] == 0) || (E[3] == 0));
}

/* ==================== Decode ==================== */
void tinyECC::decode() {
    E[0] = 0;
    E[1] = 0;

    int pt1[2], pt2[2], buf[2];

    pt1[0] = P[0];   /* C1 */
    pt1[1] = P[1];
    pt2[0] = P[2];   /* C2 */
    pt2[1] = P[3];

    /* Calcular PrivKey * C1 */
    sclr_mult(PrivKey, pt1);
    buf[0] = E[0];
    buf[1] = p - E[1];   /* Negar el punto */

    /* M = C2 + (-PrivKey*C1) */
    add(pt2, buf);
    /* Resultado en E[0], E[1] */
}

/* ==================== Scalar Multiply ==================== */
void tinyECC::sclr_mult(int k, int pt[2]) {
    int Q[2] = {0, 0};
    int Pcur[2];
    Pcur[0] = pt[0];
    Pcur[1] = pt[1];

    /* Encontrar el MSB */
    int msb = -1;
    for (int i = 31; i >= 0; i--) {
        if ((k >> i) & 1) {
            msb = i;
            break;
        }
    }

    if (msb < 0) {
        /* k == 0 => PAI */
        E[0] = 0;
        E[1] = 0;
        return;
    }

    for (int j = 0; j <= msb; j++) {
        if ((k >> j) & 1) {
            add(Q, Pcur);
            Q[0] = E[0];
            Q[1] = E[1];
        }
        add(Pcur, Pcur);
        Pcur[0] = E[0];
        Pcur[1] = E[1];
    }

    E[0] = Q[0];
    E[1] = Q[1];
}

/* ==================== Point Addition ==================== */
void tinyECC::add(int pt1[2], int pt2[2]) {
    E[0] = 0;
    E[1] = 0;

    long int A[2], B[2];
    A[0] = pt1[0];
    A[1] = pt1[1];
    B[0] = pt2[0];
    B[1] = pt2[1];

    /* PAI + PAI = PAI */
    if (isPAI(pt1) && isPAI(pt2)) {
        E[0] = 0;
        E[1] = 0;
        return;
    }

    /* PAI + Q = Q */
    if (pt1[0] == 0 && pt1[1] == 0) {
        E[0] = pt2[0];
        E[1] = pt2[1];
        return;
    }

    /* P + PAI = P */
    if (pt2[0] == 0 && pt2[1] == 0) {
        E[0] = pt1[0];
        E[1] = pt1[1];
        return;
    }

    long long int slope = 0;
    long int rx = 0, ry = 0;

    if ((A[0] == B[0]) && (A[1] == B[1])) {
        /* Point doubling */
        if (A[1] % p == 0) {
            E[0] = 0;
            E[1] = 0;
            return;
        }
        slope = ((3 * (A[0] * A[0])) + a) * inverse(2 * A[1]);
        rx = ((slope * slope) - (2 * A[0])) % p;
        ry = ((slope * (A[0] - rx)) - A[1]) % p;
    } else {
        if ((B[0] - A[0]) % p == 0) {
            /* Secante vertical => PAI */
            E[0] = 0;
            E[1] = 0;
            return;
        }
        slope = (B[1] - A[1]) * inverse(B[0] - A[0]);
        rx = ((slope * slope) - (A[0] + B[0])) % p;
        ry = ((slope * (A[0] - rx)) - A[1]) % p;
    }

    if (rx < 0) {
        rx = p + rx;
    }
    if (ry < 0) {
        ry = p + ry;
    }

    E[0] = static_cast<int>(rx);
    E[1] = static_cast<int>(ry);
}

/* ==================== Signature (ECDSA-like) ==================== */
void tinyECC::genSig() {
    int n = 997;
    int s = 0;
    int x = 0;
    int k = 0;
    int e = 0;
    long int buf = 0;

    E[0] = 0;
    E[1] = 0;

    while (s == 0 || x == 0) {
#ifdef ARDUINO
        k = random(1, p - 1);
#else
        k = (rand() % (p - 2)) + 1;
#endif

        TempArr[0] = Pbase[0];
        TempArr[1] = Pbase[1];
        sclr_mult(k, TempArr);

        x = E[0] % n;   /* r */

        e = m % n;

        long int ki = inverse1(k);
        long int bi = (e + (PrivKey * x));

        buf = (ki * bi) % n;
        s = static_cast<int>(buf);
    }

    Sig[0] = x;   /* r */
    Sig[1] = s;   /* s */
}

bool tinyECC::verifySig() {
    int n = 997;

    int r = Sig[0];
    int s = Sig[1];

    if (r >= p || s >= p) {
        return false;
    }

    long int e = m % n;
    long int w = inverse1(s) % n;

    long int u1 = (e * w) % n;
    long int u2 = (r * w) % n;

    /* u1 * Pbase */
    TempArr[0] = PbaseSer[0];
    TempArr[1] = PbaseSer[1];
    sclr_mult(static_cast<int>(u1), TempArr);
    int P1[2];
    P1[0] = E[0];
    P1[1] = E[1];

    /* u2 * PubKey */
    TempArr[0] = PubKey[0];
    TempArr[1] = PubKey[1];
    sclr_mult(static_cast<int>(u2), TempArr);
    int P2[2];
    P2[0] = E[0];
    P2[1] = E[1];

    add(P1, P2);
    int P3[2];
    P3[0] = E[0];
    P3[1] = E[1];

    if (isPAI(P3)) {
        return false;
    }

    if (P3[0] == r) {
        return true;
    }

    return false;
}

/* ==================== Utilidades ==================== */
int tinyECC::isPAI(int *point) {
    return ((point[0] == 0) && (point[1] == 0));
}

long int tinyECC::inverse(long int num) {
    if (num < 0) {
        num = p + num;
    }
    for (int i = 1; i < p; i++) {
        if (((num * i) % p) == 1) {
            return i;
        }
    }
    return 0;
}

int tinyECC::inverse1(int num) {
    long int n = 997;
    int x = num;
    if (num < 0) {
        num = n + num;
    }
    for (int i = 1; i < n; i++) {
        if (((x * i) % n) == 1) {
            return i;
        }
    }
    return 0;
}

