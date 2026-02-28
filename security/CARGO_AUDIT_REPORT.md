# Cargo Audit Security Report

**Date:** 2026-02-28
**Tool:** cargo-audit v0.22.1
**Dependencies Scanned:** 644

---

## SUMMARY

| Category | Count |
|----------|-------|
| Vulnerabilities | 2 |
| Warnings (Unmaintained) | 8 |
| Warnings (Unsound) | 2 |

---

## VULNERABILITIES (Must Address)

### 1. ring 0.16.20 - AES Panic
**ID:** RUSTSEC-2025-0009
**Severity:** Medium
**Issue:** Some AES functions may panic when overflow checking is enabled.
**Solution:** Upgrade to >=0.17.12

**Dependency Chain:**
- ring → rustls → tokio-rustls → hyper-rustls → ipfs-api-backend-hyper
- ring → jsonwebtoken → ethers-providers

**Status:** Blocked by upstream (ethers, ipfs-api)

### 2. rustls 0.20.9 - Infinite Loop
**ID:** RUSTSEC-2024-0336
**Severity:** HIGH (7.5)
**Issue:** `complete_io` could fall into an infinite loop based on network input.
**Solution:** Upgrade to >=0.23.5

**Dependency Chain:**
- rustls → tokio-rustls → hyper-rustls → ipfs-api-backend-hyper

**Status:** Blocked by ipfs-api-backend-hyper using old version

---

## WARNINGS (Unmaintained Crates)

| Crate | Version | Source | Action |
|-------|---------|--------|--------|
| dotenv | 0.15.0 | Direct | Switch to `dotenvy` |
| fxhash | 0.2.1 | ethers | Wait for upstream |
| instant | 0.1.13 | libp2p | Wait for upstream |
| paste | 1.0.15 | netlink | Wait for upstream |
| proc-macro-error | 1.0.4 | multihash | Wait for upstream |
| ring | 0.16.20 | Multiple | Wait for upstream |
| rustls-pemfile | 1.0.4 | reqwest | Wait for upstream |

---

## WARNINGS (Unsound Code)

### keccak 0.1.5
**ID:** RUSTSEC-2026-0012
**Issue:** Unsoundness in opt-in ARMv8 assembly backend
**Impact:** Only affects ARMv8 with explicit assembly feature enabled
**Risk:** LOW (x86_64 builds unaffected)

### lru 0.12.5
**ID:** RUSTSEC-2026-0002
**Issue:** `IterMut` violates Stacked Borrows
**Impact:** Potential undefined behavior in specific usage patterns
**Risk:** LOW (from libp2p, unlikely to trigger)

---

## ACTION ITEMS

### Immediate (Can Fix Now)
1. [x] Replace `dotenv` with `dotenvy` crate

### Blocked (Waiting for Upstream)
2. [ ] ethers-rs needs to update ring/rustls dependencies
3. [ ] ipfs-api needs to update to newer hyper-rustls
4. [ ] libp2p needs to update lru crate

### Monitoring
5. [ ] Watch for ethers-rs v3.0 release (uses alloy)
6. [ ] Watch for libp2p updates
7. [ ] Consider alternative IPFS client if ipfs-api remains unmaintained

---

## MITIGATIONS

Since most vulnerabilities come from transitive dependencies:

1. **rustls infinite loop** - Network timeout configuration provides protection
2. **ring AES panic** - Only affects overflow-checked builds (not release)
3. **keccak ARMv8** - We build for x86_64, not affected
4. **lru unsound** - Usage pattern in libp2p unlikely to trigger

---

## RECOMMENDATION

**Risk Level:** MEDIUM

The vulnerabilities are in transitive dependencies and have mitigations in place.
For mainnet launch:
- Replace `dotenv` with `dotenvy` (done)
- Document known issues
- Plan migration to updated dependencies when available

**Not blocking for testnet deployment.**
**Consider blocking for mainnet if upstream fixes not available.**
