# Assignment 1 — Ethereum Data Structures & Proof-of-Inclusion
**Course:** CPSC 8810 — Blockchain & Web   
**Description:**  
This assignment implements a simplified Ethereum-style Modified Merkle Patricia Trie (MPT) and demonstrates how proof-of-inclusion (PoI) works for verifying transactions efficiently.

---

## 🔍 Project Overview
The goal of this assignment was to design and implement key Ethereum data structures and use them to:

- Build an MPT from a list of 42 transactions.
- Compute the block’s transaction root hash.
- Generate a proof-of-inclusion for a specific transaction index.
- Verify the proof against the root hash.
- Show that modifying a transaction or the proof causes verification to fail.
- Perform a full self-check to confirm trie integrity and PoI correctness.

This project models how Ethereum light clients verify data without downloading the full blockchain.

---

## 🧩 Key Components

### **1. RLP Serialization**
- Converts integers, bytes, and lists into Ethereum’s compact Recursive Length Prefix format.
- Ensures consistent hashing and storage.

### **2. Trie Nodes**
- **Leaf nodes**: store final values and remaining key paths.  
- **Extension nodes**: compress long shared prefixes.  
- **Branch nodes**: contain 16 possible children (0–F) and optionally a value.

### **3. Trie Construction**
- Keys (transaction indices) are converted into nibble paths.
- Values (transactions encoded in RLP) are inserted.
- Root hash acts as a fingerprint for the dataset.

---

## ▶️ How to Run

### **1. Build the Trie**
```bash
python trie_poi.py --build
