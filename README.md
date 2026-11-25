# anchor-upgrade-check

Detects a Solana program upgrade and checks the new binary against its Anchor IDL before you trade through it.

I trade on Solana with bots I wrote. A venue I traded through upgraded its programs without notice and without a new SDK or IDL release, and before my bot went back to building its own transactions for it (meanwhile it routed through an aggregator), I needed to know what the new binary contained. This is a standalone rewrite of the tooling I used for that.

It has five commands:

- `watch` reads a program's deploy slot and upgrade authority, compares them with a stored baseline, finds the transaction that redeployed it, and exits non-zero on a change until you accept it.
- `dump` saves the deployed ELF.
- `fetch-idl` derives the program's on-chain Anchor IDL account, decompresses it and saves the JSON.
- `scan` checks a binary against an IDL in both directions: what the IDL names that the binary lacks, and what the binary names that the IDL does not.
- `simulate` runs `simulateTransaction` unsigned and requires an expected outcome, so a test can fail.

It does not decompile or diff program logic. A clean scan says the instructions, events, accounts and error messages the IDL describes are present and nothing unexplained was added to the instruction list; it does not say they behave as before. It never signs or sends a transaction. It is pure Python with no dependencies.

## How it works

### watch

An upgradeable program is two accounts. The program account only points to a programdata account, whose first 45 bytes are a header: a `u32` tag, the `u64` slot of the last deploy, and an optional 32-byte upgrade authority. The ELF follows.

- **Header only.** `watch` reads the 45-byte header with a `dataSlice`, so a check every few minutes costs two small account reads and a block-time lookup, not a download of the binary.
- **Slot and authority.** The loader rewrites the deploy slot whenever it redeploys a program, so a new slot means the code you checked may not be the code that runs. A new upgrade authority also counts as a change: someone else can now replace the code.
- **The deploy transaction.** A redeploy writes the programdata account, so the transaction that did it is in that account's signature list at exactly the deploy slot. `watch` searches the newest 25 signatures (`--sigs`) and prints the signers and the top-level instructions, for example `bpf-upgradeable-loader:upgrade`.
- **A change keeps failing.** The first run records a baseline. After a change, every run exits 1 until you run it with `--accept`, which should happen only after the new binary has been scanned and simulated.
- **No verdict is not "no change".** If the RPC fails or the account is not an upgradeable program, the exit code is 3 and the baseline is left alone. Several programs can be watched in one call; any change gives 1, which takes precedence over 3.

```
$ anchor-upgrade-check watch <PROGRAM_ID>
program      <PROGRAM_ID>
programdata  <PROGRAMDATA_ADDRESS>
deploy slot  300,000,900 (2026-01-01T12:00:00Z)
authority    <UPGRADE_AUTHORITY>
read at slot 300,001,000
state        CHANGED
             slot: 300,000,500 -> 300,000,900
deploy tx    <SIGNATURE> (2026-01-01T12:00:00Z) err None
             signers ['<UPGRADE_AUTHORITY>']
             instructions ['bpf-upgradeable-loader:upgrade']
$ echo $?
1
```

### dump

`dump` reads the whole programdata account and cuts the ELF out of it. The account is usually larger than the binary (it is allocated with room to grow), so the end has to be found. Stripping trailing zero bytes is the obvious way and is wrong: an ELF can end in zero bytes, since the section header table is usually last and its last entry ends in zero fields. A binary cut short that way hashes differently from the same binary built locally. `dump` takes the end from the ELF's own headers (the furthest end of any header table, segment or section, each bounds-checked) and falls back to stripping zeros only when the bytes do not parse as ELF, and says so. It prints the binary's SHA-256, so two dumps, or a dump and a local build, can be compared.

### fetch-idl

`anchor idl init` stores the IDL at an address that depends only on the program id: `base` is the program's PDA with no seeds, and the IDL account is `create_with_seed(base, "anchor:idl", program_id)`. Deriving a PDA needs an Ed25519 on-curve test. That is implemented in pure Python to match curve25519-dalek's `decompress`, which the runtime uses: the sign bit is ignored, y is reduced mod p, and the point exists when (y^2 - 1) / (d*y^2 + 1) is a square. Bumps are tried from 255 down to 1, as the SDK does. The tests pin the Solana SDK's own PDA and seed vectors, and cross-check random keys and seeds against `solders` when it is installed.

The account is an 8-byte discriminator (`sha256("internal:IdlAccount")[:8]`: Anchor declares this account in its `internal` namespace, not the usual `account`), the IDL authority, a `u32` length, then zlib-compressed JSON. `fetch-idl` checks the discriminator and the length, and refuses an account at that address that is not owned by the program itself.

The on-chain IDL is written by whoever holds the IDL authority, separately from the program upgrade, so it can lag the binary. That is the reason to scan it against the binary rather than trust it.

### scan

`scan` is offline. It takes a binary (from `dump`, `solana program dump`, or a local build) and an IDL (from `fetch-idl` or an SDK package) and runs three checks.

**Discriminators.** Every instruction, event and account in an Anchor IDL has an 8-byte discriminator. Each is searched in two forms:

- as 8 contiguous bytes, for constants the compiler left in read-only data;
- as an sBPF `lddw` instruction loading it as a 64-bit immediate. This is how dispatch code usually compares the first 8 bytes of instruction data, and a byte search cannot see it, because `lddw` is 16 bytes with the constant split in two:

```
byte    0    1      2-3    4-7          8    9    10-11  12-15
        18   dst    0000   disc[0:4]    00   00   0000   disc[4:8]
```

An `lddw` match counts only inside an executable section and on an 8-byte instruction boundary; the same 16 bytes in data are not a load. Without a section table, every offset counts and the report says so.

**Instruction-name logs.** Anchor's dispatcher logs `Instruction: <Name>` for every instruction, so a name in the binary that the IDL lacks is the most direct sign of a new instruction. Rust packs string literals with no separator, so the name's end cannot be read off the bytes: each occurrence is matched to the longest IDL name its text starts with. An occurrence that matches no IDL name is a finding, shown with the bytes that follow it. One IDL name matched by two occurrences (`Deposit` and a new `DepositAll`) is also a finding, because each instruction is logged once. Anchor's own IDL-management instructions (`IdlCreateAccount`, `IdlWrite` and five more) are logged the same way and listed in no IDL; they are recognised and listed separately.

**Error messages.** Each IDL error message must be present. The text right after the last-placed known message is printed for a human, because messages added at the end of the error enum land there.

Both IDL formats are handled. Anchor 0.30+ IDLs carry their discriminators; for older ones they are recomputed as Anchor does (`sha256("global:<snake_case_name>")`, `sha256("event:<Name>")`, `sha256("account:<Name>")`, first 8 bytes).

The scan fails (exit 1) when anything is unaccounted for, including discriminators it could not check. On a synthetic binary built by the tests, with one discriminator removed, one instruction added and one error message added:

```
$ anchor-upgrade-check scan program.so idl.json
binary   680 bytes; ELF64, machine 247, e_flags 0x0, code in ['.text']
idl      toy_vault, Anchor 0.30+ (discriminators from the IDL)

discriminators (contiguous bytes / sBPF lddw immediate pair)
  instruction initialize     afaf6d1f0d989bed  lddw at .text+0x8
  instruction deposit        f223c68952e1f2b6  contiguous at .rodata+0x0
  instruction withdraw       b712469c946da122  MISSING
  instruction set_authority  85fa25156ea31a79  lddw at .text+0x20
  event       Deposited      6f8d1a2da1236439  lddw at .text+0x38
  account     Vault          d308e82b02987577  contiguous at .rodata+0x8

instruction-name logs ('Instruction: <Name>'): 5 in the binary, 4/4 IDL names found
  not in IDL:  'MigrateProgram log: other literalAmount is below'

error messages: 3/3 found
  text after the last-placed message (code 6002); new messages would be here:
    'Fees exceed the cap'
    '.text'
    '.rodata'
    '.shstrtab'

RESULT: 2 finding(s)
  - instruction withdraw: discriminator b712469c946da122 not found
  - 'Instruction: ' followed by 'MigrateProgram log: other literalAmount is below' starts with no IDL instruction name
```

### simulate

A simulation that returns "no error" proves little if the harness could not have returned anything else. So every run states the outcome it expects (`--expect-error 101`, `--expect-error InvalidAccountData`, or `--expect-error ok`), and the first runs against a new binary should be positive controls that must fail with a known code. For an Anchor program without a fallback function, an instruction whose first 8 bytes match no instruction must fail with framework error 101, `InstructionFallbackNotFound`. When that comes back as predicted, the program, the RPC and the error parsing are all working, and a clean result on the real instruction means something.

- **Nothing is signed.** Every signature in the transaction is overwritten with zeros before the request, and the request sets `sigVerify: false` and `replaceRecentBlockhash: true`. No private key is ever loaded, and even a signed transaction passed in by mistake leaves the machine unsigned, so whoever runs the RPC cannot submit it.
- **Exact parsing first.** The transaction is parsed to its last byte (legacy or v0) before the signatures are blanked. Anything else is refused rather than guessed at.
- **The fee payer.** Simulation still charges the fee, so the payer must be an existing system account with some SOL. Nothing signs for it, so it does not have to be a key you hold, but the RPC operator sees whichever address you use.

A transaction can come from any builder as a base64 file, or from a small JSON spec that `simulate` compiles into an unsigned legacy transaction (key order as the Solana SDK produces it; a test compares the bytes with `solders`):

```json
{
  "payer": "<FUNDED_ADDRESS>",
  "instructions": [
    {
      "program_id": "<PROGRAM_ID>",
      "accounts": [{"pubkey": "<SOME_ACCOUNT>", "signer": false, "writable": true}],
      "data_hex": "ffffffffffffffff"
    }
  ]
}
```

```
$ anchor-upgrade-check simulate --ix control.json --expect-error 101
transaction  legacy, 1 signature(s) sent as zeros, 177 bytes
result       Custom 101 in instruction 0
anchor       Program log: AnchorError occurred. Error Code: InstructionFallbackNotFound. Error Number: 101. Error Message: Fallback functions are not supported.
units        1,424
logs (last 4 of 4)
  Program <PROGRAM_ID> invoke [1]
  Program log: AnchorError occurred. Error Code: InstructionFallbackNotFound. Error Number: 101. Error Message: Fallback functions are not supported.
  Program <PROGRAM_ID> consumed 1424 of 200000 compute units
  Program <PROGRAM_ID> failed: custom program error: 0x65
expected     Custom 101
PASS
```

## Usage

Python 3.11 or later, no dependencies.

```
pip install .
anchor-upgrade-check --help        # or: python -m anchor_upgrade_check --help
```

Every command that reads the chain uses the public mainnet endpoint unless `SOLANA_RPC_URL` or `--rpc` names another. The URL is never printed, because many providers put the API key in it. The client retries rate limits and node-behind errors and honours `Retry-After`.

A typical sequence after `watch` reports a change:

```
anchor-upgrade-check dump <PROGRAM_ID> -o program.so
anchor-upgrade-check fetch-idl <PROGRAM_ID> -o idl.json      # or the IDL from the SDK you built against
anchor-upgrade-check scan program.so idl.json
anchor-upgrade-check simulate --ix control.json --expect-error 101
anchor-upgrade-check simulate --ix real_call.json --expect-error ok
anchor-upgrade-check watch <PROGRAM_ID> --accept
```

| Exit code | Meaning |
|---|---|
| 0 | Pass: unchanged, baseline recorded, binary matches the IDL, or the expected simulation outcome |
| 1 | The check failed: a change, a mismatch, or a different simulation outcome (`fetch-idl`: no IDL account) |
| 2 | Usage error |
| 3 | No verdict: the chain could not be read, or an input could not be parsed |

## Tests

```
pip install pytest
python -m pytest
```

The tests run offline on synthetic data built inside them (`tests/synth.py`): a toy Anchor IDL in both formats, a hand-assembled sBPF ELF with planted discriminators (as `lddw` pairs and as contiguous bytes), upgradeable-loader accounts, and a scripted RPC. Most of them are controls that prove a check can fail:

- one discriminator left out of the binary must be reported missing;
- a discriminator planted only as an `lddw` pair must be absent from a plain byte search and still found;
- the same `lddw` bytes off an instruction boundary, or in a data section, must not count;
- an extra `Instruction: Migrate`, a `DepositAll` beside `Deposit`, a missing and a new error message must each be reported;
- the ELF ends in zero bytes, and stripping zeros must cut it short where `dump` does not;
- a new deploy slot or a new authority must fail until accepted, and a failed read must give 3 and leave the baseline alone;
- a transaction passed in with non-zero signatures must reach the RPC with zero signatures and `sigVerify` off; a wrong expected code must fail;
- the RPC client must never put the URL in an error and must honour `Retry-After`.

PDA derivation is checked against the Solana SDK's published vectors, and against `solders` (random keys, seeds and a compiled message) when it is installed. One opt-in test reads a real program: set `AUC_LIVE_PROGRAM=<PROGRAM_ID>`.

Synthetic tests share their author's assumptions, so I also ran the tool once against a large public Anchor program (a 1.5 MB binary; an on-chain IDL with 66 instructions, 6 events and 12 accounts). 83 of the 84 discriminators were found, 63 of them only as `lddw` pairs, which a plain byte search would have reported missing, and the `simulate` positive control above returned 101 as predicted. The one not found is an instruction the on-chain IDL still lists but whose discriminator and log string are both absent from the deployed binary. The same run exposed two mistakes the fixtures shared with the code: `fetch-idl` refused the real IDL account because both used the `account:` namespace for its discriminator, and `scan` reported Anchor's built-in IDL instructions as unknown. Both are fixed, and both now have tests: the discriminator is pinned to the bytes read from chain.

## Limitations

- It checks presence, not behaviour. A changed account layout, a new field at the end of an event, or a changed check inside an instruction is invisible to `scan` unless it adds or removes a discriminator, a log name or an error message. `simulate` covers only the paths you build transactions for.
- A missing discriminator means "look", not "absent". A compiler can compare the constant in two 32-bit halves or build it another way, and the scan would not see it. The report prints `e_flags`, where the SBPF version is recorded: later SBPF versions (SIMD-0173) remove `lddw`, and for them only the contiguous search applies.
- Only 8-byte discriminators are searched. Shorter custom discriminators (possible since Anchor 0.31) are reported as not checked, and the scan fails.
- Instruction-name logs can be compiled out. If the binary has none, that is noted and not counted. Unknown names are shown with the bytes that follow them, which often run into the next literal.
- The text after the last error message is for a human to read; new error codes themselves are not recovered.
- For older IDLs, discriminators are recomputed from camelCase names. A Rust name with a digit after an underscore (`init_2`) became `init2` in the IDL and cannot be recovered.
- Only the upgradeable loader. `watch` and `dump` refuse loader-v4 and non-upgradeable programs.
- `fetch-idl` reads only the Anchor `anchor:idl` account, not other on-chain metadata programs. An IDL from an SDK package can be passed to `scan` as a file.
- `watch` polls; it tells you after the fact, at your polling interval. A changed slot means a redeploy; compare SHA-256 hashes from `dump` to see whether the bytes changed. The deploy transaction is looked up among the newest `--sigs` signatures of the programdata account, with `maxSupportedTransactionVersion` 0.
- `simulate` builds legacy transactions only (no address lookup tables); a prebuilt v0 transaction can be passed as a file. A simulation runs against the RPC node's current state, which can differ from the state your real transaction would land in.
- The public endpoint is rate-limited. The client is meant for checks every few minutes, not for high-frequency polling.

## Authorship

Designed by me; implemented with AI coding agents under my design and review; I can walk through every part of it.

## License

MIT. See [LICENSE](LICENSE).
