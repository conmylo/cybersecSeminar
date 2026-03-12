"""
Εργασία 6 — CPA AES-128
ΑΠΘ | Google.org Cybersecurity Seminars
"""

import numpy as np
import h5py
import matplotlib.pyplot as plt
import os

# ─── Φάκελος αποθήκευσης γραφημάτων ──────────────────────────
OUTPUT_DIR = "figures_project6"
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


# ─── Ζήτημα #1 — Φόρτωση Dataset ─────────────────────────────
def load_dataset(filepath):
    print("\n" + "─" * 50)
    print("  ΖΗΤΗΜΑ #1 — Φόρτωση & Επιθεώρηση Dataset")
    print("─" * 50)

    with h5py.File(filepath, 'r') as f:
        print(f"Κλειδιά HDF5: {list(f.keys())}")
        traces     = np.array(f['trace'])
        plaintexts = np.array(f['m'])
        ciphers    = np.array(f['c'])

    print(f"traces     : shape={traces.shape}, dtype={traces.dtype}")
    print(f"plaintexts : shape={plaintexts.shape}, dtype={plaintexts.dtype}")
    print(f"ciphertexts: shape={ciphers.shape}, dtype={ciphers.dtype}")
    print(f"Αριθμός ιχνών  : {traces.shape[0]}")
    print(f"Δείγματα/ίχνος : {traces.shape[1]}")

    return traces, plaintexts, ciphers


# ─── Ζήτημα #2 — Οπτικοποίηση Ιχνών ──────────────────────────
def visualize_traces(traces):
    print("\n" + "─" * 50)
    print("  ΖΗΤΗΜΑ #2 — Οπτικοποίηση Ιχνών")
    print("─" * 50)

    fig, axes = plt.subplots(2, 1, figsize=(14, 8))

    for i in range(10):
        axes[0].plot(traces[i], alpha=0.4, linewidth=0.6)
    axes[0].set_title('Πρώτα 10 Ίχνη Κατανάλωσης Ισχύος')
    axes[0].set_xlabel('Χρονικό Δείγμα')
    axes[0].set_ylabel('Κατανάλωση Ισχύος')
    axes[0].grid(True, alpha=0.3)

    mean_trace = np.mean(traces[:100], axis=0)
    std_trace  = np.std(traces[:100],  axis=0)
    x = np.arange(len(mean_trace))
    axes[1].plot(mean_trace, color='navy', linewidth=0.8, label='Μέσο ίχνος')
    axes[1].fill_between(x,
                         mean_trace - std_trace,
                         mean_trace + std_trace,
                         alpha=0.25, color='steelblue', label='±1σ')
    axes[1].set_title('Μέσο Ίχνος ± Τυπική Απόκλιση (100 traces)')
    axes[1].set_xlabel('Χρονικό Δείγμα')
    axes[1].set_ylabel('Κατανάλωση Ισχύος')
    axes[1].legend()
    axes[1].grid(True, alpha=0.3)

    plt.tight_layout()
    path = os.path.join(OUTPUT_DIR, "fig1_power_traces.png")
    plt.savefig(path, dpi=150)
    plt.close()
    print(f"Αποθηκεύτηκε: {path}")


# ─── Ζήτημα #3 — Επιλογή Στόχου AES ──────────────────────────
def target_demo(plaintexts):
    print("\n" + "─" * 50)
    print("  ΖΗΤΗΜΑ #3 — Επιλογή Στόχου AES")
    print("─" * 50)

    byte_idx   = 0
    example_pt = plaintexts[0, byte_idx]
    key_byte   = 0x2B
    xor_val    = int(example_pt) ^ key_byte
    sbox_out   = SBOX[xor_val]
    hw         = bin(sbox_out).count('1')

    print(f"Στόχος : v = SBox( plaintext[{byte_idx}] XOR key[{byte_idx}] )")
    print(f"Γύρος  : 1ος — SubBytes αμέσως μετά AddRoundKey")
    print(f"plaintext[0][0] = 0x{example_pt:02X}")
    print(f"key[0]          = 0x{key_byte:02X}")
    print(f"XOR             = 0x{xor_val:02X}")
    print(f"S-Box output    = 0x{sbox_out:02X}")
    print(f"Hamming Weight  = {hw}")


# ─── Ζήτημα #4 — Μοντέλο Διαρροής (Hamming Weight) ───────────
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

def verify_and_plot_hw():
    print("\n" + "─" * 50)
    print("  ΖΗΤΗΜΑ #4 — Μοντέλο Διαρροής (Hamming Weight)")
    print("─" * 50)

    # Επαλήθευση
    known = {0x00: 0, 0x01: 1, 0x0F: 4, 0xFF: 8, 0x55: 4, 0xAA: 4}
    print(f"\n{'Τιμή':>6}  {'Αναμ.':>6}  {'Υπολ.':>6}  {'OK':>4}")
    for val, expected in known.items():
        computed = hamming_weight(val)
        ok = "✓" if computed == expected else "✗"
        print(f"0x{val:02X}    {expected:>6}  {computed:>6}  {ok}")

    # Στατιστικά
    hw_vals = np.array([hamming_weight(int(SBOX[i])) for i in range(256)])
    print(f"\nΜέσος HW   : {hw_vals.mean():.3f}")
    print(f"Τυπ. απόκλ.: {hw_vals.std():.3f}")

    # Γράφημα
    counts = np.bincount(hw_vals, minlength=9)
    plt.figure(figsize=(7, 4))
    plt.bar(range(9), counts, color='steelblue', edgecolor='navy', alpha=0.85)
    plt.xlabel('Hamming Weight')
    plt.ylabel('Πλήθος τιμών S-Box')
    plt.title('Κατανομή HW για όλες τις εξόδους S-Box')
    plt.xticks(range(9))
    plt.grid(axis='y', alpha=0.3)
    for i, c in enumerate(counts):
        if c > 0:
            plt.text(i, c + 0.5, str(c), ha='center', fontsize=9)
    plt.tight_layout()
    path = os.path.join(OUTPUT_DIR, "fig2_hw_distribution.png")
    plt.savefig(path, dpi=150)
    plt.close()
    print(f"Αποθηκεύτηκε: {path}")


# ─── Εκτέλεση ─────────────────────────────────────────────────
if __name__ == "__main__":
    traces, plaintexts, ciphers = load_dataset('atmega328p.hdf5')
    visualize_traces(traces)
    target_demo(plaintexts)
    verify_and_plot_hw()

    print("\n" + "─" * 50)
    print(f"  Ολοκλήρωση — γραφήματα στον φάκελο: {OUTPUT_DIR}/")
    print("─" * 50)