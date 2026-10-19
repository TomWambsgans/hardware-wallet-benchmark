/*
 * SPHINCS+ benchmark commands (leanVM's variant; BLAKE2s, raw SHA-256 or Keccak-256),
 * from github.com/TomWambsgans/hardware-wallet-benchmark (sources in
 * cmd/sphincs/). Timings are CPU cycles from systick_cycles(), printed as two
 * 32-bit halves <hi> <lo>.
 *
 *   sphincs-bench <hash> <count>    count compressions (Keccak: permutations)
 *     -> OK <cycles hi> <cycles lo> <count>
 *   sphincs-keygen <hash> <seed>    32-byte seed (hex); key kept in RAM
 *     -> OK <P hex> <root hex> <cycles hi> <cycles lo> <compressions>
 *   sphincs-sign <hash> <message>   32-byte message (hex)
 *     -> PROGRESS sig <offset> <hex> ... (the 4924-byte signature)
 *     -> OK <cycles hi> <cycles lo> <compressions> <randomizer trials> <c0> <c1> <c2>
 *
 * <hash> is "blake2s", "sha256" or "keccak256".
 */

#include <trezor_rtl.h>

#include <rtl/cli.h>
#include <sys/systick.h>

#include "sphincs/blake2s.h"
#include "sphincs/hash.h"
#include "sphincs/keccak.h"
#include "sphincs/sha256.h"
#include "sphincs/sphincs.h"

static spx_key_t g_keys[HASH_COUNT];
static bool      g_have_key[HASH_COUNT];
static uint8_t   g_sig[SPX_SIG_BYTES];
static bool      g_setup_done;

static bool parse_hash(cli_t* cli, hash_id_t* hash) {
  const char* name = cli_arg(cli, "hash");
  if (strcmp(name, "blake2s") == 0) {
    *hash = HASH_BLAKE2S;
  } else if (strcmp(name, "sha256") == 0) {
    *hash = HASH_SHA256;
  } else if (strcmp(name, "keccak256") == 0) {
    *hash = HASH_KECCAK256;
  } else {
    cli_error_arg(cli, "Expecting hash blake2s, sha256 or keccak256.");
    return false;
  }
  if (!g_setup_done) {
    hash_setup();
    g_setup_done = true;
  }
  g_hash = *hash;
  g_compressions = 0;
  return true;
}

#define HI(x) ((unsigned long)((x) >> 32))
#define LO(x) ((unsigned long)((x) & 0xFFFFFFFFu))

static void to_hex(char* out, const uint8_t* data, size_t len) {
  static const char digits[] = "0123456789abcdef";
  for (size_t i = 0; i < len; i++) {
    out[2 * i] = digits[data[i] >> 4];
    out[2 * i + 1] = digits[data[i] & 15];
  }
  out[2 * len] = 0;
}

static void prodtest_sphincs_bench(cli_t* cli) {
  hash_id_t hash;
  uint32_t count;
  if (cli_arg_count(cli) != 2) {
    cli_error_arg_count(cli);
    return;
  }
  if (!parse_hash(cli, &hash)) {
    return;
  }
  if (!cli_arg_uint32(cli, "count", &count)) {
    cli_error_arg(cli, "Expecting count.");
    return;
  }
  uint32_t h[50] = {0}, m[16] = {0};
  uint64_t start = systick_cycles();
  for (uint32_t i = 0; i < count; i++) {
    if (hash == HASH_SHA256) {
      sha256_compress(h, m);
    } else if (hash == HASH_KECCAK256) {
      keccak_permute(h);
    } else {
      blake2s_compress(h, m, 64, 0xFFFFFFFFu);
    }
  }
  uint64_t cycles = systick_cycles() - start;
  cli_ok(cli, "%lu %lu %lu", HI(cycles), LO(cycles), (unsigned long)count);
}

static void prodtest_sphincs_keygen(cli_t* cli) {
  hash_id_t hash;
  uint8_t seed[32];
  size_t len = 0;
  if (cli_arg_count(cli) != 2) {
    cli_error_arg_count(cli);
    return;
  }
  if (!parse_hash(cli, &hash)) {
    return;
  }
  if (!cli_arg_hex(cli, "seed", seed, sizeof(seed), &len) || len != sizeof(seed)) {
    cli_error_arg(cli, "Expecting a 32-byte seed in hex.");
    return;
  }
  uint64_t start = systick_cycles();
  spx_keygen(&g_keys[hash], seed);
  uint64_t cycles = systick_cycles() - start;
  g_have_key[hash] = true;
  char pp[33], root[33];
  to_hex(pp, (const uint8_t*)g_keys[hash].pp, 16);
  to_hex(root, (const uint8_t*)g_keys[hash].root, 16);
  cli_ok(cli, "%s %s %lu %lu %lu", pp, root, HI(cycles), LO(cycles), (unsigned long)g_compressions);
}

static void prodtest_sphincs_sign(cli_t* cli) {
  hash_id_t hash;
  uint8_t msg[32];
  size_t len = 0;
  spx_sign_stats_t stats;
  if (cli_arg_count(cli) != 2) {
    cli_error_arg_count(cli);
    return;
  }
  if (!parse_hash(cli, &hash)) {
    return;
  }
  if (!g_have_key[hash]) {
    cli_error(cli, CLI_ERROR_FATAL, "No key for this hash: run sphincs-keygen first.");
    return;
  }
  if (!cli_arg_hex(cli, "message", msg, sizeof(msg), &len) || len != sizeof(msg)) {
    cli_error_arg(cli, "Expecting a 32-byte message in hex.");
    return;
  }
  uint64_t start = systick_cycles();
  bool ok = spx_sign(&g_keys[hash], msg, g_sig, &stats);
  uint64_t cycles = systick_cycles() - start;
  if (!ok) {
    cli_error(cli, CLI_ERROR_FATAL, "Hypertree walk did not reach the root.");
    return;
  }
  static char line[2 * 256 + 1];
  for (size_t off = 0; off < SPX_SIG_BYTES; off += 256) {
    size_t n = SPX_SIG_BYTES - off < 256 ? SPX_SIG_BYTES - off : 256;
    to_hex(line, g_sig + off, n);
    cli_progress(cli, "sig %u %s", (unsigned)off, line);
  }
  cli_ok(cli, "%lu %lu %lu %lu %lu %lu %lu", HI(cycles), LO(cycles), (unsigned long)g_compressions,
         (unsigned long)stats.digest_trials, (unsigned long)stats.counters[0],
         (unsigned long)stats.counters[1], (unsigned long)stats.counters[2]);
}

// clang-format off

PRODTEST_CLI_CMD(
  .name = "sphincs-bench",
  .func = prodtest_sphincs_bench,
  .info = "Time <count> compressions of <hash> (blake2s|sha256|keccak256)",
  .args = "<hash> <count>"
);

PRODTEST_CLI_CMD(
  .name = "sphincs-keygen",
  .func = prodtest_sphincs_keygen,
  .info = "SPHINCS+ key generation from a 32-byte hex seed",
  .args = "<hash> <seed>"
);

PRODTEST_CLI_CMD(
  .name = "sphincs-sign",
  .func = prodtest_sphincs_sign,
  .info = "SPHINCS+ signature of a 32-byte hex message",
  .args = "<hash> <message>"
);
