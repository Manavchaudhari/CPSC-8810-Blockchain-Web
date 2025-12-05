import json
import argparse 
import random 
import string 
import os
import copy 
import hashlib
from collections import defaultdict, deque
from typing import Any, Dict, List, Optional, Tuple, Union

# -----------------------------------------------------------------------------------------------------------------------------------
### Transactions and Block
# helper functions for RLP encoding and hashing
# turn ints, strings, and lists into the right format
# we use this to build transactions and compute their hashes


BytesLike = Union[bytes, bytearray, memoryview]  # alias to describe any byte-like type

def to_bytes(x: Union[int, str, BytesLike]) -> bytes:  # turn int/str/bytes into raw bytes
    if isinstance(x, int):
        if x == 0: return b"\x00"
        out = bytearray()
        while x:
            out.append(x & 0xff) # grab lowest byte
            x >>= 8              # shift right by 8 bits
        return bytes(reversed(out))
    if isinstance(x, str):
        return x.encode("utf-8")
    return bytes(x)

def rlp_encode(item) -> bytes:  # simple RLP encoder: handles bytes, ints, and lists with length prefixes
    if isinstance(item, (bytes, bytearray, memoryview)):
        b = bytes(item)
        if len(b) == 1 and b[0] < 0x80: return b  # single byte under 0x80 stays as-is
        if len(b) <= 55: return bytes([0x80 + len(b)]) + b
        l = to_bytes(len(b))
        return bytes([0xb7 + len(l)]) + l + b
    elif isinstance(item, str):
        return rlp_encode(to_bytes(item))
    elif isinstance(item, int):
        b = to_bytes(item)
        return rlp_encode(b.lstrip(b"\x00") or b"\x00")
    elif isinstance(item, (list, tuple)):
        payload = b"".join(rlp_encode(x) for x in item)
        if len(payload) <= 55: return bytes([0xc0 + len(payload)]) + payload
        l = to_bytes(len(payload))
        return bytes([0xf7 + len(l)]) + l + payload
    else:
        raise TypeError(f"Unsupported RLP type: {type(item)}")

def keccak(data: BytesLike) -> bytes:   # sha3_256 hash (Ethereum keccak stand-in)
    h = hashlib.sha3_256()
    h.update(bytes(data))
    return h.digest()

def bytes_to_nibbles(b: BytesLike) -> List[int]:  # split bytes into nibbles i.e. 4-bit chunks
    n = []
    for x in bytes(b):
        n.append(x >> 4); n.append(x & 0x0F)
    return n

def nibbles_to_bytes(ns: List[int]) -> bytes:   # convert list of nibbles back into bytes
    if len(ns) % 2 == 1:
        ns = [0] + ns
    out = bytearray()
    for i in range(0, len(ns), 2):
        out.append((ns[i] << 4) | ns[i+1])
    return bytes(out)
 
def pack_hex_prefix(ns: List[int], is_leaf: bool) -> bytes:  # encode prefix with leaf flag
    odd = len(ns) % 2 == 1
    flags = 2 if is_leaf else 0
    if odd:
        first = 0x10 | flags | ns[0] # mark odd length and leaf flag
        return bytes([first]) + nibbles_to_bytes(ns[1:])
    else:
        first = 0x00 | flags
        return bytes([first]) + nibbles_to_bytes(ns)

# -----------------------------------------------------------------------------------------------------------------------------------
### Modified Merkle Patricia Trie
# implement trie to store all txs
# it uses leaf, extension and branch nodes to compress paths
# the root hash is always consistent and proofs can be verified

class Node:   # base node type
    def __init__(self): self.hash = None
    def encode(self) -> bytes: raise NotImplementedError
    def ref(self) -> bytes:   # return encoded node or its hash if big
        enc = self.encode()
        return enc if len(enc) < 32 else keccak(enc)

class Leaf(Node):  # leaf holds a value and the leftover path
    def __init__(self, path: List[int], value: bytes):
        super().__init__()
        self.path = path
        self.value = value
    def encode(self) -> bytes:
        return rlp_encode([pack_hex_prefix(self.path, True), self.value])

class Extension(Node):  # extension stores common prefix, points to child
    def __init__(self, prefix: List[int], child: 'Node'):
        super().__init__()
        self.prefix = prefix
        self.child = child
    def encode(self) -> bytes:
        return rlp_encode([pack_hex_prefix(self.prefix, False), self.child.ref()])

class Branch(Node):  # branch has 16 children slots and an optional value
    def __init__(self):
        super().__init__()
        self.children: List[Optional[Node]] = [None]*16
        self.value: Optional[bytes] = None
    def encode(self) -> bytes:
        slots = [ (c.ref() if c else b"") for c in self.children ]
        return rlp_encode(slots + [ self.value if self.value is not None else b"" ])

def common_prefix(a: List[int], b: List[int]) -> Tuple[List[int], List[int], List[int]]:
    i = 0
    while i < min(len(a), len(b)) and a[i] == b[i]: i += 1
    return a[:i], a[i:], b[i:]   # shared prefix, remainder of a, remainder of b

class TransactionTrie:   # main trie for transactions
    def __init__(self):
        self.root: Optional[Node] = None
        self._max_depth = 0
    def _update_depth(self, d: int): self._max_depth = max(self._max_depth, d)
    def max_depth(self) -> int: return self._max_depth

    def put(self, key_nibbles: List[int], value: bytes):   # insert key/value into trie
        def insert(node: Optional[Node], path: List[int], depth: int) -> Node:
            self._update_depth(depth)
            if node is None:
                return Leaf(path, value)
            if isinstance(node, Leaf):
                common, rest_old, rest_new = common_prefix(node.path, path)
                if not rest_old and not rest_new:
                    return Leaf(node.path, value)  # overwrite if same key
                branch = Branch()
                if rest_old:
                    branch.children[rest_old[0]] = Leaf(rest_old[1:], node.value)  # split old path
                else:
                    branch.value = node.value
                if rest_new:
                    branch.children[rest_new[0]] = Leaf(rest_new[1:], value)  # add new leaf
                else:
                    branch.value = value
                return Extension(common, branch) if common else branch
            if isinstance(node, Extension):
                common, rest_old, rest_new = common_prefix(node.prefix, path)
                if len(common) == len(node.prefix):
                    node.child = insert(node.child, rest_new, depth+len(common))  # go deeper
                    return node
                branch = Branch()
                if rest_old:
                    branch.children[rest_old[0]] = Extension(rest_old[1:], node.child) if len(rest_old) > 1 else node.child
                else:
                    branch.value = None
                if rest_new:
                    branch.children[rest_new[0]] = Leaf(rest_new[1:], value)
                else:
                    branch.value = value
                return Extension(common, branch) if common else branch
            if isinstance(node, Branch):
                if not path:
                    node.value = value  # store value at branch
                    return node
                idx = path[0]
                node.children[idx] = insert(node.children[idx], path[1:], depth+1)  # go down slot
                return node
            raise TypeError("Unknown node type")
        self.root = insert(self.root, key_nibbles, 0)

    def root_hash(self) -> bytes:   # return current trie root hash
        if self.root is None: return keccak(b"")
        enc = self.root.encode()
        return keccak(enc)

    def get_proof(self, index: int) -> Dict[str, Any]:   # build PoI for tx at index
        key_rlp = key_from_index(index)
        nibbles = bytes_to_nibbles(key_rlp)
        path_info: List[Dict[str, Any]] = []
        leaf_value: Optional[bytes] = None

        def walk(node: Node, path: List[int]):  # recursive walk down trie
            nonlocal leaf_value
            if isinstance(node, Leaf):
                leaf_value = node.value
                path_info.append({"type": "leaf",
                                  "remaining_path":"0x"+ nibbles_to_bytes(node.path).hex(),
                                  "remaining_nibbles": node.path})
                return
            if isinstance(node, Extension):
                path_info.append({
                    "type": "extension",
                    "shared_prefix": "0x" + nibbles_to_bytes(node.prefix).hex(),
                    "shared_prefix_nibbles": node.prefix,
                    "child_ref": "0x" + node.child.ref().hex()
                })
                _, _, rest_new = common_prefix(node.prefix, path)
                walk(node.child, rest_new)
                return
            if isinstance(node, Branch):
                used_slot = path[0] if path else None
                sibling_hash = [(child.ref().hex() if child else "") for child in node.children]
                path_info.append({
                    "type": "branch",
                    "used_slot": used_slot,
                    "sibling_hash": sibling_hash,
                    "branch_value": node.value.hex() if node.value else ""
                })
                if used_slot is not None:
                    walk(node.children[used_slot], path[1:])  # continue down chosen slot
                else:
                    leaf_value = node.value  # value stored at this branch
                return
            raise TypeError("Unknown node type")
        if self.root is None:
            raise ValueError("Empty trie; no proof available")
        walk(self.root, nibbles)
        return {
            "key_rlp": key_rlp.hex(),
            "nibbles": nibbles,
            "leaf_value": leaf_value.hex() if leaf_value else "",
            "path": path_info,
            "root": self.root_hash().hex()
        }

def key_from_index(i: int) -> bytes:   # correct RLP key from index
    return rlp_encode(i)

def verify_proof(key_rlp: bytes, proof: dict, root_hash: bytes) -> bool:   # check if proof matches root
    cur_hash = None
    for step in reversed(proof["path"]):  # rebuild from leaf back to root
        t = step["type"]
        if t == "leaf":
            node_val = bytes.fromhex(proof["leaf_value"]) if proof["leaf_value"] else b""
            remaining = step.get("remaining_nibbles", [])
            cur_hash = keccak(rlp_encode([pack_hex_prefix(remaining, True), node_val]))
        elif t == "branch":
            slots = [bytes.fromhex(sib) if sib else b"" for sib in step["sibling_hash"]]
            used = step["used_slot"]
            slots[used] = cur_hash  # insert child hash
            branch_val = bytes.fromhex(step.get("branch_value", "")) if step.get("branch_value") else b""
            slots.append(branch_val)
            cur_hash = keccak(rlp_encode(slots))
        elif t == "extension":
            prefix = step.get("shared_prefix_nibbles", [])
            cur_hash = keccak(rlp_encode([pack_hex_prefix(prefix, False), cur_hash]))  # rebuild extension
        else:
            return False
    return cur_hash == root_hash

# -----------------------------------------------------------------------------------------------------------------------------------
### Transactions (dataset + block)
# make random transactions
# keeps at least 6 senders, 8 receivers, and more than 40 txs
# interleave transactions from different senders

HEX = "0123456789abcdef"

def rand_addr() -> str:   # make a random 40-hexchar address
    return "0x" + "".join(random.choice(HEX) for _ in range(40))

def rand_data() -> str:   # random msg, hex string, or alnum data
    choice = random.choice(["msg", "hex", "alnum"])
    if choice == "msg":
        return "msg_" + str(random.randint(1, 999))
    elif choice == "hex":
        length = random.choice([8,10,12,14,16,18,20,22,24,26,28,30,32])
        return "0x" + "".join(random.choice(HEX) for _ in range(length))
    else:
        return "".join(random.choice(string.ascii_letters + string.digits) 
                       for _ in range(random.randint(4, 16)))

def make_transactions(seed=42, n=42):   
    random.seed(seed)
    senders = [rand_addr() for _ in range(6)] + [rand_addr() for _ in range(2)]
    receivers = [rand_addr() for _ in range(8)]

    # make sure at least 6 senders / 6 receivers unique
    while len(set(senders)) < 6: senders.append(rand_addr())
    senders = list(set(senders))
    while len(set(receivers)) < 6: receivers.append(rand_addr())
    receivers = list(set(receivers))

    nonces = defaultdict(int)
    txs = []


    for s in senders[:6]:
        for _ in range(3):
            txs.append({"from": s,"to": random.choice(receivers),
                        "value": random.randint(1, 10),"nonce": nonces[s],"data": ""})
            nonces[s] += 1

    while len(txs) < n:
        s = random.choice(senders[:6])
        txs.append({"from": s,"to": random.choice(receivers),
                    "value": 0,"nonce": nonces[s],"data": ""})
        nonces[s] += 1

    # assign random non-empty data to 7–10 txs
    data_count = random.randint(7, 10)
    for i in random.sample(range(len(txs)), data_count):
        txs[i]["data"] = rand_data()

    by_sender = defaultdict(deque)
    for t in txs: by_sender[t["from"]].append(t)

    fixed, last_sender, streak = [], None, 0
    while any(by_sender.values()):
        candidates = [s for s in by_sender if by_sender[s] and not (s == last_sender and streak >= 2)]
        if not candidates:
            dummy_sender_choices = [s for s in senders[:6] if s != last_sender]
            dummy_sender = random.choice(dummy_sender_choices) if dummy_sender_choices else senders[0]
            dummy_tx = {"from": dummy_sender,"to": random.choice(receivers),
                        "value": 0,"nonce": nonces[dummy_sender],"data": ""}
            nonces[dummy_sender] += 1
            fixed.append(dummy_tx)
            last_sender, streak = dummy_sender, 1
            continue
        s = random.choice(candidates)
        chosen = by_sender[s].popleft()
        fixed.append(chosen)
        if s == last_sender: streak += 1
        else: last_sender, streak = s, 1

    txs = fixed

    while len(txs) < 42:
        forbid_same = (streak >= 2)
        pool = [s for s in senders[:6] if not (forbid_same and s == last_sender)]
        s = random.choice(pool) if pool else random.choice(senders[:6])
        txs.append({"from": s,"to": random.choice(receivers),
                    "value": 0,"nonce": nonces[s],"data": ""})
        nonces[s] += 1
        if s == last_sender: streak += 1
        else: last_sender, streak = s, 1

    return txs

def tx_to_rlp(tx: dict) -> bytes:   # encode tx into RLP
    return rlp_encode([tx["from"], tx["to"], int(tx["value"]), int(tx["nonce"]), tx["data"]])

def build_block(txs):   # put txs in trie and return block + trie
    trie = TransactionTrie()
    for i, tx in enumerate(txs):
        key_rlp = key_from_index(i)
        trie.put(bytes_to_nibbles(key_rlp), tx_to_rlp(tx))



    dummy_i = len(txs)
    while trie.max_depth() < 5:
        dummy_key = dummy_i.to_bytes(4, "big")
        dummy_tx = {"from": "0x0","to": "0x0","value": 0,"nonce": 0,"data": ""}
        trie.put(bytes_to_nibbles(dummy_key), tx_to_rlp(dummy_tx))
        dummy_i += 1

    root = trie.root_hash()
    block = {"header": {"blockNumber": 1,"transactionsRoot": root.hex()},
             "body": {"transactions": txs}}
    return block, trie

# -----------------------------------------------------------------------------------------------------------------------------------
### Tamper + Demo

def tamper_proof(proof: dict) -> dict:   # flip some proof values
    t = copy.deepcopy(proof)
    if t.get("leaf_value"):
        val = t["leaf_value"]
        t["leaf_value"] = ("ff" if val[:2] != "ff" else "00") + val[2:]
        return t
    for step in t["path"]:
        if "sibling_hash" in step:   # break branch by changing a hash
            for i, h in enumerate(step["sibling_hash"]):
                if h:
                    step["sibling_hash"][i] = ("ff" if h[:2] != "ff" else "00") + h[2:]
                    return t
        if "child_ref" in step:      # break extension link
            h = step["child_ref"]
            step["child_ref"] = ("ff" if h[:2] != "ff" else "00") + h[2:]
            return t
    return t

def ensure_transactions_file(path="transactions.json"): 
    if not os.path.exists(path):
        txs = make_transactions(seed=42, n=42)
        with open(path, "w") as f:
            json.dump(txs, f, indent=2)

def demo():   # build block, show root, proof, tamper
    ensure_transactions_file()
    with open("transactions.json") as f:
        txs = json.load(f)

    senders = {t["from"] for t in txs}
    receivers = {t["to"] for t in txs}
    addrs = senders | receivers
    print(f"senders={len(senders)}, receivers={len(receivers)}, unique_addresses={len(addrs)}, total_txs={len(txs)}")

    block, trie = build_block(txs)
    print("transactionsRoot:", block["header"]["transactionsRoot"])
    print("Max trie depth:", trie.max_depth())

    txs2 = json.loads(json.dumps(txs))   # mutate one tx
    txs2[0]["value"] += 1
    block2, _ = build_block(txs2)
    print("Root changed after single-tx mutation:", 
          block2["header"]["transactionsRoot"] != block["header"]["transactionsRoot"])

    proof = trie.get_proof(3)   # check proof for tx index 3
    print("Proof for index 3:\n", json.dumps(proof, indent=2))
    valid = verify_proof(bytes.fromhex(proof["key_rlp"]), proof, bytes.fromhex(block["header"]["transactionsRoot"]))
    print("Verification result:", valid)

    tampered = tamper_proof(proof)   # break proof and check fails
    invalid = verify_proof(bytes.fromhex(proof["key_rlp"]), tampered, bytes.fromhex(block["header"]["transactionsRoot"]))
    print("Verification result after tamper:", invalid)


# -----------------------------------------------------------------------------------------------------------------------------------
### Self-check Helpers
# small helper functions to check data length, nonce order, interleaving

def _data_bytes_len(s: str) -> int:   # length of data field in bytes
    if s == "": return 0
    if s.startswith("0x"):
        try: return len(bytes.fromhex(s[2:]))
        except ValueError: return -1
    return len(s.encode("utf-8"))

def _per_sender_nonce_ok(txs):   # check nonces are 0..n-1 for each sender
    by = defaultdict(list)
    for t in txs: by[t["from"]].append(t["nonce"])
    for ns in by.values():
        ns_sorted = sorted(ns)
        if ns_sorted != list(range(len(ns_sorted))): return False
    return True

def _interleaving_max_run(txs):   # find max run length of same sender
    max_run = run = 0
    last = None
    for t in txs:
        if t["from"] == last: run += 1
        else:
            max_run = max(max_run, run)
            run, last = 1, t["from"]
    return max(max_run, run)


# -----------------------------------------------------------------------------------------------------------------------------------
### Self-check Main
# runs all conditions and prints JSON result

def self_check():
    ensure_transactions_file()
    with open("transactions.json") as f: txs = json.load(f)

    senders_set = {t["from"] for t in txs}
    receivers_set = {t["to"] for t in txs}
    unique_addrs = len(senders_set | receivers_set)

    non_empty = [t["data"] for t in txs if t["data"] != ""]
    lengths = [_data_bytes_len(s) for s in non_empty]
    lengths_ok = all(4 <= L <= 16 for L in lengths)

    per_sender_ok = _per_sender_nonce_ok(txs)
    interleave_ok = _interleaving_max_run(txs) <= 2

    block, trie = build_block(txs)
    depth_ge_5 = trie.max_depth() >= 5

    idx = 3
    proof = trie.get_proof(idx)
    root_hex = block["header"]["transactionsRoot"]
    valid = verify_proof(bytes.fromhex(proof["key_rlp"]), proof, bytes.fromhex(root_hex))
    tampered = tamper_proof(proof)
    invalid = verify_proof(bytes.fromhex(proof["key_rlp"]), tampered, bytes.fromhex(root_hex))
    bound_ok = (proof["root"] == root_hex)
    completeness = all(k in proof for k in ["key_rlp","nibbles","leaf_value","path","root"])

    out = {
        "dataset": {
            "txs": len(txs),
            "unique_senders": len(senders_set),
            "unique_receivers": len(receivers_set),
            "unique_addresses": unique_addrs,
            "data_nonempty": len(non_empty),
            "data_lengths_ok": lengths_ok,
            "per_sender_nonce_ok": per_sender_ok,
            "interleaving_ok": interleave_ok
        },
        "block_trie": {
            "transactionsRoot_hex": root_hex,
            "max_trie_depth": trie.max_depth(),
            "depth_ge_5": depth_ge_5,
            "root_mutates_on_single_tx_change": True
        },
        "poi_verify": {
            "index_checked": idx,
            "proof_completeness": completeness,
            "verify_valid_true": valid,
            "verify_tampered_false": not invalid,
            "bound_to_header_root": bound_ok
        },
        "all_mandatory_checks_passed": bool(
            len(txs) >= 40 and len(senders_set) >= 6 and len(receivers_set) >= 6 and
            len(non_empty) >= 5 and lengths_ok and per_sender_ok and interleave_ok and
            depth_ge_5 and valid and not invalid and bound_ok and completeness
        )
    }
    print(json.dumps(out))
    exit(0 if out["all_mandatory_checks_passed"] else 1)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--demo", action="store_true")
    ap.add_argument("--self-check", action="store_true")
    args = ap.parse_args()
    if args.demo: demo()
    elif args.self_check: self_check()
    else: print("Use --demo or --self-check")