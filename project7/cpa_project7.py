"""
Εργασία 7 — CPA AES-128: Επίθεση & Ανάκτηση Κλειδιού
ΑΠΘ | Google.org Cybersecurity Seminars
Κωνσταντίνος Μυλωνάς - mli25036
"""

import numpy as np
import h5py
import matplotlib.pyplot as plt
import os

# ─── Φάκελος αποθήκευσης γραφημάτων ──────────────────────────
OUTPUT_DIR = "figures_project7"
os.makedirs(OUTPUT_DIR, exist_ok=True)

# AES S-Box (FIPS-197)
SBOX = np.array([
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
], dtype=np.uint8)

def hamming_weight(x):
    if isinstance(x, np.ndarray):
        result = np.zeros(x.shape, dtype=np.uint8)
        tmp = x.astype(np.uint32)
        while tmp.any():
            result += (tmp & 1).astype(np.uint8)
            tmp >>= 1
        return result
    else:
        count = 0
        while x:
            count += x & 1
            x >>= 1
        return count


# ─── Φόρτωση Dataset ───────────────────────────────────────────
def load_dataset(filepath):
    with h5py.File(filepath, 'r') as f:
        traces     = np.array(f['trace'])
        plaintexts = np.array(f['m'])
        ciphers    = np.array(f['c'])
    return traces, plaintexts, ciphers


# ─── Ζήτημα #Α — Υπολογισμός Υποθετικής Διαρροής ─────────────
def compute_hypothetical_leakage(plaintexts, byte_idx=0, debug_n=10):
    print("\n" + "─" * 50)
    print("  ΖΗΤΗΜΑ #Α — Υπολογισμός Υποθετικής Διαρροής")
    print("─" * 50)

    num_traces = plaintexts.shape[0]

    # Debug με λίγα ίχνη πρώτα
    print(f"\nDebug με {debug_n} ίχνη:")
    H_debug = np.zeros((256, debug_n), dtype=np.uint8)
    for k in range(256):
        for i in range(debug_n):
            intermediate    = SBOX[int(plaintexts[i, byte_idx]) ^ k]
            H_debug[k, i]   = hamming_weight(int(intermediate))
    print(f"H_debug shape : {H_debug.shape}")
    print(f"H_debug[0,:5] : {H_debug[0, :5]}  (υπόθεση k=0x00, πρώτα 5 ίχνη)")
    print(f"H_debug[0x2B,:5]: {H_debug[0x2B, :5]}  (υπόθεση k=0x2B, πρώτα 5 ίχνη)")

    # Πλήρης υπολογισμός — vectorized
    print(f"\nΠλήρης υπολογισμός ({num_traces} ίχνη)...")
    pt_col = plaintexts[:, byte_idx].astype(np.uint16)  # (N,)
    H = np.zeros((256, num_traces), dtype=np.uint8)
    for k in range(256):
        intermediates = SBOX[pt_col ^ k]                # (N,)
        H[k, :]       = hamming_weight(intermediates)

    print(f"H shape       : {H.shape}  (256 υποθέσεις × {num_traces} ίχνη)")
    print(f"H μέσος HW    : {H.mean():.3f}  (αναμενόμενο ≈ 4.0)")

    return H


# ─── Ζήτημα #Β — CPA ──────────────────────────────────────────
def compute_cpa(traces, H):
    print("\n" + "─" * 50)
    print("  ΖΗΤΗΜΑ #Β — CPA (Υπολογισμός Συσχέτισης)")
    print("─" * 50)

    num_hyp, num_traces = H.shape
    num_samples         = traces.shape[1]

    # Pearson correlation — vectorized
    # H: (256, N),  traces: (N, S)
    # Αποτέλεσμα R: (256, S)

    H_f = H.astype(np.float32)
    T_f = traces.astype(np.float32)

    H_mean = H_f.mean(axis=1, keepdims=True)          # (256, 1)
    T_mean = T_f.mean(axis=0, keepdims=True)           # (1, S)

    H_c = H_f - H_mean                                 # (256, N)
    T_c = T_f - T_mean                                 # (N, S)

    numerator   = H_c @ T_c                            # (256, S)
    H_std = np.sqrt((H_c ** 2).sum(axis=1, keepdims=True))  # (256, 1)
    T_std = np.sqrt((T_c ** 2).sum(axis=0, keepdims=True))  # (1, S)

    R = numerator / (H_std * T_std + 1e-12)            # (256, S)

    # Μέγιστη απόλυτη συσχέτιση ανά υπόθεση κλειδιού
    max_corr = np.max(np.abs(R), axis=1)               # (256,)

    print(f"R shape       : {R.shape}  (256 υποθέσεις × {num_samples} δείγματα)")
    print(f"Max |R| range : [{max_corr.min():.4f}, {max_corr.max():.4f}]")

    # Γράφημα: max συσχέτιση ανά υπόθεση κλειδιού
    best_k = np.argmax(max_corr)
    plt.figure(figsize=(12, 4))
    plt.plot(max_corr, color='steelblue', linewidth=0.8, label='Max |correlation|')
    plt.axvline(x=best_k, color='red', linestyle='--', linewidth=1.2,
                label=f'Best: 0x{best_k:02X}')
    plt.xlabel('Υπόθεση κλειδιού (0–255)')
    plt.ylabel('Μέγιστη |συσχέτιση Pearson|')
    plt.title('CPA — Μέγιστη Συσχέτιση ανά Υπόθεση Κλειδιού')
    plt.legend()
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    path = os.path.join(OUTPUT_DIR, "fig1_cpa_max_correlation.png")
    plt.savefig(path, dpi=150)
    plt.close()
    print(f"Αποθηκεύτηκε: {path}")

    return R, max_corr


# ─── Ζήτημα #Γ — Ανάκτηση & Επαλήθευση Byte Κλειδιού ─────────
def recover_key_byte(R, max_corr, byte_idx=0):
    print("\n" + "─" * 50)
    print("  ΖΗΤΗΜΑ #Γ — Ανάκτηση & Επαλήθευση Byte Κλειδιού")
    print("─" * 50)

    # Ανάκτηση
    best_k         = np.argmax(max_corr)
    best_sample    = np.argmax(np.abs(R[best_k]))
    best_corr_val  = R[best_k, best_sample]

    print(f"Ανακτημένο byte κλειδιού : 0x{best_k:02X}")
    print(f"Χρονικό δείγμα διαρροής  : {best_sample}")
    print(f"Συσχέτιση Pearson        : {best_corr_val:.4f}")

    # Επαλήθευση
    key_hex    = "2B7E151628AED2A6ABF7158809CF4F3C"
    key_bytes  = bytes.fromhex(key_hex)
    expected   = key_bytes[byte_idx]
    result     = "✓ ΣΩΣΤΟ" if best_k == expected else f"✗ ΛΑΘΟΣ (αναμενόταν 0x{expected:02X})"
    print(f"Αναμενόμενο byte         : 0x{expected:02X}")
    print(f"Αποτέλεσμα               : {result}")

    # Γράφημα: correlation trace για το σωστό και λανθασμένα keys
    plt.figure(figsize=(12, 4))
    for k in range(256):
        if k != best_k:
            plt.plot(R[k], color='lightgray', linewidth=0.3, alpha=0.5)
    plt.plot(R[best_k], color='red', linewidth=1.2,
             label=f'Ανακτημένο key byte: 0x{best_k:02X}')
    plt.xlabel('Χρονικό Δείγμα')
    plt.ylabel('Συσχέτιση Pearson')
    plt.title('CPA — Correlation Traces για όλες τις Υποθέσεις Κλειδιού')
    plt.legend()
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    path = os.path.join(OUTPUT_DIR, "fig2_cpa_correlation_traces.png")
    plt.savefig(path, dpi=150)
    plt.close()
    print(f"Αποθηκεύτηκε: {path}")

    return best_k


# ─── Ζήτημα #Δ — δεν παράγει κώδικα (θεωρητικό) ──────────────


# ─── Εκτέλεση ─────────────────────────────────────────────────
if __name__ == "__main__":
    traces, plaintexts, ciphers = load_dataset('atmega328p.hdf5')

    H              = compute_hypothetical_leakage(plaintexts, byte_idx=0)
    R, max_corr    = compute_cpa(traces, H)
    best_k         = recover_key_byte(R, max_corr, byte_idx=0)

    print("\n" + "─" * 50)
    print(f"  Ολοκλήρωση — γραφήματα στον φάκελο: {OUTPUT_DIR}/")
    print("─" * 50)