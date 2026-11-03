// ncguard-unpacker: recovers the original AMD64 PE image from an ncguard-packed executable.
//
// Pipeline:
//   1. Find the XOR-obfuscated records table that describes each packed payload, then recover
//      the payload XOR keys from the packer stub (falling back to keys.txt).
//   2. Strip each payload's repeating XOR key and split it into framed regions.
//   3. Decompress every region with ncguard's LZSS variant.
//   4. Reassemble module images from the section regions.
//   5. Classify the main module's directory stream back into PE data-directory slots and
//      recover the entry point from the security-cookie initializer.
//   6. Write a flat (RVA == file offset) PE with a synthesized header, named after the input and
//      its file version. Everything else stays in memory.

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <map>
#include <optional>
#include <span>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace ncg {
    using Byte = std::uint8_t;
    using Bytes = std::vector<Byte>;
    using U32 = std::uint32_t;
    using U64 = std::uint64_t;
    namespace fs = std::filesystem;

    struct FormatError : std::runtime_error {
        using std::runtime_error::runtime_error;
    };

    // ---- Constants -------------------------------------------------------------------------------

    constexpr U64 kSectionAlign = 0x1000;
    constexpr U64 kFileAlign = 0x200;
    constexpr std::size_t kHeaderSize = 0x400;        // SizeOfHeaders of the rebuilt PE
    constexpr std::size_t kPackedHeaderSize = 0x1000; // header bytes kept from the packed file
    constexpr U64 kPayloadDelta = 0x600;              // record ptr + delta = payload file offset

    constexpr U32 kScnCode = 0x20;           // IMAGE_SCN_CNT_CODE
    constexpr U32 kScnInitData = 0x40;       // IMAGE_SCN_CNT_INITIALIZED_DATA
    constexpr U32 kScnShared = 0x10000000;   // IMAGE_SCN_MEM_SHARED
    constexpr U32 kScnWrite = 0x80000000;    // IMAGE_SCN_MEM_WRITE

    // Data-directory slots.
    namespace dir {
    constexpr int Export = 0, Import = 1, Resource = 2, Exception = 3, Security = 4, BaseReloc = 5,
                  Debug = 6, Tls = 9, LoadConfig = 10, Iat = 12, DelayImport = 13;
    }
    constexpr std::array<const char*, 16> kDirNames = {
        "EXPORT", "IMPORT", "RESOURCE", "EXCEPTION", "SECURITY", "BASERELOC", "DEBUG", "ARCH",
        "GLOBALPTR", "TLS", "LOADCFG", "BOUNDIMP", "IAT", "DELAYIMP", "COM+", "COM+2" };

    // IMAGE_LOAD_CONFIG_DIRECTORY64.Size values emitted by known toolchain versions.
    constexpr std::array<U32, 17> kLoadConfigSizes = {
        0x40, 0x48, 0x50, 0x54, 0x58, 0x5c, 0x60, 0x64, 0x68,
        0x70, 0x80, 0x90, 0x94, 0xa0, 0x128, 0x130, 0x140 };
    constexpr std::size_t kLoadConfigCookie = 0x58;   // offset of SecurityCookie (a VA)

    // ---- Byte helpers ----------------------------------------------------------------------------

    std::string hex(U64 value)
    {
        std::ostringstream s;
        s << std::hex << value;
        return s.str();
    }

    std::string hex_bytes(std::span<const Byte> bytes)
    {
        std::ostringstream s;
        s << std::hex << std::setfill('0');
        for (Byte b : bytes)
            s << std::setw(2) << unsigned(b);
        return s.str();
    }

    U64 align_up(U64 v, U64 a)
    {
        if (v > std::numeric_limits<U64>::max() - (a - 1))
            throw FormatError("alignment overflow");

        return (v + a - 1) & ~(a - 1);
    }

    U32 u32(U64 v)
    {
        if (v > std::numeric_limits<U32>::max())
            throw FormatError("PE field exceeds 32 bits");

        return static_cast<U32>(v);
    }

    std::size_t host_size(U64 v)
    {
        if (v > std::numeric_limits<std::size_t>::max())
            throw FormatError("buffer exceeds host size");

        return static_cast<std::size_t>(v);
    }

    U64 load_le(const Byte* p, std::size_t n)
    {
        U64 v = 0;
        for (std::size_t i = 0; i < n; ++i)
            v |= U64(p[i]) << (8 * i);
        return v;
    }

    std::int32_t load_i32(const Byte* p)
    {
        return static_cast<std::int32_t>(static_cast<U32>(load_le(p, 4)));
    }

    struct View {
        const Bytes& bytes;
        std::size_t start, count;

        explicit View(const Bytes& b)
            : bytes(b), start(0), count(b.size())
        {
        }

        View(const Bytes& b, std::size_t off, std::size_t len)
            : bytes(b), start(std::min(off, b.size())), count(std::min(len, b.size() - start))
        {
        }

        const Byte* data() const
        {
            return bytes.data() + start;
        }

        void require(std::size_t off, std::size_t n) const
        {
            if (off > count || n > count - off)
                throw FormatError("truncated binary structure");
        }

        U64 get(std::size_t off, std::size_t n) const
        {
            require(off, n);
            return load_le(data() + off, n);
        }

        Byte b(std::size_t off) const
        {
            return static_cast<Byte>(get(off, 1));
        }

        std::uint16_t w(std::size_t off) const
        {
            return static_cast<std::uint16_t>(get(off, 2));
        }

        U32 d(std::size_t off) const
        {
            return static_cast<U32>(get(off, 4));
        }

        U64 q(std::size_t off) const
        {
            return get(off, 8);
        }
    };

    void put(Bytes& b, std::size_t off, U64 v, std::size_t n)
    {
        View(b).require(off, n);
        for (std::size_t i = 0; i < n; ++i)
            b[off + i] = static_cast<Byte>(v >> (8 * i));
    }

    void copy_range(Bytes& dst, std::size_t to, const Bytes& src, std::size_t from, std::size_t n)
    {
        View(dst).require(to, n);
        View(src).require(from, n);
        std::copy_n(src.begin() + from, n, dst.begin() + to);
    }

    // Copies up to `len` bytes at `off`, clamped to the buffer.
    Bytes slice(const Bytes& b, std::size_t off, std::size_t len)
    {
        const View v(b, off, len);
        return Bytes(v.data(), v.data() + v.count);
    }

    void xor_in_place(Bytes& b, std::span<const Byte> key)
    {
        if (key.empty())
            throw FormatError("empty XOR key");

        for (std::size_t i = 0; i < b.size(); ++i)
            b[i] ^= key[i % key.size()];
    }

    // NUL-terminated string at `rva`, reading at most `limit` bytes.
    std::string cstring(const Bytes& image, U32 rva, std::size_t limit = 32)
    {
        const View v(image, rva, limit);
        return std::string(v.data(), std::find(v.data(), v.data() + v.count, Byte(0)));
    }

    std::string to_lower(std::string s)
    {
        for (char& c : s)
            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

        return s;
    }

    bool ends_with_ci(const std::string& s, std::string_view tail)
    {
        return to_lower(s).ends_with(tail);
    }

    // CodeView PDB 7.0 debug record.
    bool has_rsds_signature(const Bytes& image, U32 rva)
    {
        const View v(image, rva, 4);
        return v.count == 4 && std::equal(v.data(), v.data() + 4, "RSDS");
    }

    Bytes from_hex(std::string_view s)
    {
        if (s.size() % 2)
            throw FormatError("odd hex length");

        auto nibble = [](char c) {
            if (c >= '0' && c <= '9')
                return c - '0';

            if (c >= 'a' && c <= 'f')
                return c - 'a' + 10;

            if (c >= 'A' && c <= 'F')
                return c - 'A' + 10;

            throw FormatError(std::string("invalid hex digit '") + c + "'");
        };
        Bytes b;
        for (std::size_t i = 0; i < s.size(); i += 2)
            b.push_back(static_cast<Byte>(nibble(s[i]) << 4 | nibble(s[i + 1])));
        return b;
    }

    // ---- File I/O --------------------------------------------------------------------------------

    // Payload XOR keys for an ncguard build: record 0 uses KEY0, every later record KEYN.
    struct Keys {
        Bytes key0, keyn;
    };

    constexpr const char* kKeysFile = "keys.txt";

    // Key file format, one key per line, names case-insensitive, '#' starts a comment and
    // whitespace inside the hex is ignored:
    //   KEY0 = 1fa94f38...
    //   KEYN = 22caa631...
    Keys load_keys(const fs::path& p)
    {
        std::ifstream f(p);
        if (!f)
            throw std::runtime_error("cannot open key file: " + p.string() +
                                     " (expected lines \"KEY0 = <hex>\" and \"KEYN = <hex>\")");

        Keys keys;
        std::string line;
        for (int n = 1; std::getline(f, line); ++n) {
            auto error = [&](const std::string& why) {
                return std::runtime_error(p.string() + ":" + std::to_string(n) + ": " + why);
            };
            std::string text;
            for (char c : line.substr(0, line.find('#')))
                if (!std::isspace(static_cast<unsigned char>(c)))
                    text.push_back(c);

            if (text.empty())
                continue;

            const auto eq = text.find('=');
            if (eq == std::string::npos)
                throw error("expected NAME = <hex>");

            const std::string name = to_lower(text.substr(0, eq));
            Bytes* key = name == "key0" ? &keys.key0 : name == "keyn" ? &keys.keyn : nullptr;
            if (!key)
                throw error("unknown key \"" + text.substr(0, eq) + "\" (expected KEY0 or KEYN)");

            try {
                *key = from_hex(std::string_view(text).substr(eq + 1));
            } catch (const FormatError& e) {
                throw error(e.what());
            }
            if (key->empty())
                throw error("empty key");
        }
        if (keys.key0.empty() || keys.keyn.empty())
            throw std::runtime_error(p.string() + ": needs both KEY0 and KEYN");

        return keys;
    }

    Bytes read_file(const fs::path& p)
    {
        std::ifstream f(p, std::ios::binary | std::ios::ate);
        if (!f)
            throw std::runtime_error("cannot open: " + p.string());

        const auto end = f.tellg();
        if (end < 0)
            throw std::runtime_error("invalid file length: " + p.string());

        Bytes b(host_size(static_cast<U64>(end)));
        f.seekg(0);
        if (!b.empty() && !f.read(reinterpret_cast<char*>(b.data()), static_cast<std::streamsize>(b.size())))
            throw std::runtime_error("cannot read: " + p.string());

        return b;
    }

    void write_file(const fs::path& p, const Bytes& b)
    {
        std::ofstream f(p, std::ios::binary | std::ios::trunc);
        if (!f)
            throw std::runtime_error("cannot create: " + p.string());

        f.write(reinterpret_cast<const char*>(b.data()), static_cast<std::streamsize>(b.size()));
        f.close();
        if (!f)
            throw std::runtime_error("cannot write: " + p.string());
    }

    // ---- Stage 1: records table ------------------------------------------------------------------
    //
    // Each 33-byte row is XORed with the 4-byte key stored in its own bytes 28..31. Plaintext:
    //   [0] tag  [1..4] payload ptr  [5..8] payload len  [9..11] meta  [12..32] name, zero padded
    // The zero padding means bytes 20..32 of an encrypted row simply repeat the key.

    constexpr std::size_t kRowSize = 33, kRowKey = 28;

    struct Row {
        Byte tag;
        U32 ptr, len;
        std::array<Byte, 3> meta;
        std::string name;
    };

    std::optional<Row> try_row(const Bytes& data, std::size_t pos)
    {
        if (pos > data.size() || data.size() - pos < kRowSize)
            return {};

        const Byte* enc = data.data() + pos;
        const Byte* key = enc + kRowKey;
        for (std::size_t j = 20; j < kRowSize; ++j)
            if (enc[j] != key[j % 4])
                return {};

        std::array<Byte, kRowSize> row;
        for (std::size_t j = 0; j < kRowSize; ++j)
            row[j] = static_cast<Byte>(enc[j] ^ key[j % 4]);

        Row r{ row[0], U32(load_le(&row[1], 4)), U32(load_le(&row[5], 4)), { row[9], row[10], row[11] }, {} };
        if (r.tag > 8 || r.ptr < 0x400 || r.len < 0x10 || r.ptr >= data.size() || r.len >= data.size() ||
            U64(r.ptr) + r.len > data.size())
            return {};

        for (std::size_t j = 12; j < kRowSize; ++j)
            if (row[j] >= 32 && row[j] < 127)
                r.name.push_back(static_cast<char>(row[j]));

        return r;
    }

    // The records table is the longest run of back-to-back rows with increasing payload pointers.
    std::vector<Row> find_records_table(const Bytes& data)
    {
        if (data.size() < kRowSize)
            throw FormatError("records table chain too short (0 rows)");

        // A row's key-repeating tail gives data[i] == data[i + 4] for a stretch of bytes, so only
        // probe row starts up to 32 bytes before each run of 8 such bytes.
        std::map<std::size_t, Row> rows;
        const std::size_t last_start = data.size() - kRowSize;
        std::size_t probed = 0, run = 0;
        for (std::size_t i = 0; i + 4 < data.size(); ++i) {
            run = data[i] == data[i + 4] ? run + 1 : 0;
            if (run < 8)
                continue;

            run = 0;
            const std::size_t pos = i - 7;
            const std::size_t hi = std::min(pos + 1, last_start);
            for (std::size_t p = std::max(probed, pos > 32 ? pos - 32 : 0); p < hi; ++p)
                if (auto r = try_row(data, p))
                    rows.emplace(p, std::move(*r));

            probed = std::max(probed, hi);
        }

        auto successor = [&](std::map<std::size_t, Row>::const_iterator it) {
            auto next = rows.find(it->first + kRowSize);
            return next != rows.end() && next->second.ptr > it->second.ptr ? next : rows.cend();
        };
        auto best = rows.cend();
        std::size_t best_len = 0;
        for (auto start = rows.cbegin(); start != rows.cend(); ++start) {
            std::size_t len = 1;
            for (auto it = successor(start); it != rows.cend(); it = successor(it))
                ++len;
            if (len > best_len) {
                best = start;
                best_len = len;
            }
        }
        if (best_len < 4)
            throw FormatError("records table chain too short (" + std::to_string(best_len) + " rows)");

        std::vector<Row> table;
        for (auto it = best; it != rows.cend(); it = successor(it))
            table.push_back(it->second);
        return table;
    }

    // ---- Stage 1b: key extraction ----------------------------------------------------------------
    //
    // The packer stub builds each 48-byte payload key on the stack one `mov byte [rsp+disp], imm8`
    // at a time, then passes it to an XOR helper. KEY0 is normally built just before a call to that
    // helper and KEYN between two consecutive calls to it. Every 48-byte run of such stores near a
    // pair of calls is a candidate; a candidate is accepted when it decrypts a records-table payload.

    constexpr std::size_t kKeySize = 48;
    constexpr std::size_t kMaxCallGap = 0x2000;    // max distance between two calls to the helper
    constexpr std::size_t kMaxPrologue = 0x2000;   // how far before a call a key build may start

    using Key = std::array<Byte, kKeySize>;

    struct StackStore {
        U32 disp;
        Byte value;
    };

    // Decodes `mov byte ptr [rsp+disp], imm8` (C6 04 24 / C6 44 24 disp8 / C6 84 24 disp32) in [lo, hi).
    std::vector<StackStore> stack_byte_stores(const Bytes& b, std::size_t lo, std::size_t hi)
    {
        hi = std::min(hi, b.size());
        lo = std::min(lo, hi);
        std::vector<StackStore> stores;
        for (std::size_t i = lo; i + 4 <= hi;) {
            if (b[i] != 0xc6 || b[i + 2] != 0x24) {
                ++i;
                continue;
            }

            const Byte modrm = b[i + 1];
            if (modrm == 0x04) {
                stores.push_back({ 0, b[i + 3] });
                i += 4;
            } else if (modrm == 0x44 && i + 5 <= hi) {
                stores.push_back({ b[i + 3], b[i + 4] });
                i += 5;
            } else if (modrm == 0x84 && i + 8 <= hi) {
                stores.push_back({ U32(load_le(&b[i + 3], 4)), b[i + 7] });
                i += 8;
            } else {
                ++i;
            }
        }
        return stores;
    }

    // Every window of kKeySize consecutive stack offsets, ordered by offset.
    std::vector<Key> key_windows(std::vector<StackStore> stores)
    {
        // Stable, so the instruction order decides between repeated writes to one offset.
        std::stable_sort(stores.begin(), stores.end(), [](const StackStore& a, const StackStore& b) {
            return a.disp < b.disp;
        });
        std::vector<Key> keys;
        std::size_t run = 0;
        for (std::size_t i = 0; i < stores.size(); ++i) {
            const bool contiguous = i > 0 && U64(stores[i].disp) == U64(stores[i - 1].disp) + 1;
            run = contiguous ? run + 1 : 1;
            if (run < kKeySize)
                continue;

            Key key;
            for (std::size_t j = 0; j < kKeySize; ++j)
                key[j] = stores[i + 1 - kKeySize + j].value;

            keys.push_back(key);
        }
        return keys;
    }

    struct KeyCandidate {
        std::size_t first_call;
        std::optional<std::size_t> second_call;   // set for keys built between two calls
        Key key;
    };

    struct KeyCandidates {
        std::vector<KeyCandidate> before_call, between_calls;
    };

    KeyCandidates find_key_candidates(const Bytes& data)
    {
        // Group `call rel32` sites by target (in file-offset space), keeping first-seen order.
        std::unordered_map<std::int64_t, std::size_t> group_of;
        std::vector<std::vector<std::size_t>> groups;
        constexpr std::size_t kScanStart = 0x600;   // past the PE headers
        for (std::size_t i = kScanStart; i + 5 <= data.size(); ++i) {
            if (data[i] != 0xe8)
                continue;

            const std::int64_t target = std::int64_t(i) + 5 + load_i32(&data[i + 1]);
            const auto [it, inserted] = group_of.try_emplace(target, groups.size());
            if (inserted)
                groups.emplace_back();

            groups[it->second].push_back(i);
        }

        KeyCandidates out;
        for (const auto& sites : groups) {
            for (std::size_t j = 1; j < sites.size(); ++j) {
                const std::size_t first = sites[j - 1], second = sites[j];
                if (second - first > kMaxCallGap)
                    continue;

                for (const auto& key : key_windows(stack_byte_stores(data, first + 5, second)))
                    out.between_calls.push_back({ first, second, key });

                const std::size_t lo = first > kMaxPrologue ? first - kMaxPrologue : 0;
                for (const auto& key : key_windows(stack_byte_stores(data, lo, first)))
                    out.before_call.push_back({ first, {}, key });
            }
        }
        return out;
    }

    // Number of regions `key` decodes from the row's payload, or 0 if it fails the same acceptance
    // test as decode_record. Only each frame's 4-byte length is decrypted.
    std::size_t regions_decoded(const Bytes& data, const Row& row, const Key& key)
    {
        const U64 start = U64(row.ptr) + kPayloadDelta;
        if (start > data.size() || row.len > data.size() - start)
            return 0;

        const Byte* payload = data.data() + start;
        std::size_t off = 0, regions = 0;
        while (row.len - off >= 12) {
            U32 comp = 0;
            for (std::size_t j = 0; j < 4; ++j)
                comp |= U32(payload[off + j] ^ key[(off + j) % kKeySize]) << (8 * j);

            if (!comp || comp > row.len - off - 12)
                break;

            ++regions;
            off += 12 + comp;
        }
        return off >= row.len / 2 ? regions : 0;
    }

    struct KeyMatch {
        const KeyCandidate* candidate;
        std::size_t regions;
    };

    std::vector<KeyMatch> keys_decoding(const std::vector<KeyCandidate>& candidates, const Bytes& data, const Row& row)
    {
        std::vector<KeyMatch> matches;
        for (const auto& c : candidates)
            if (const std::size_t regions = regions_decoded(data, row, c.key))
                matches.push_back({ &c, regions });

        return matches;
    }

    std::optional<std::pair<KeyMatch, KeyMatch>> distinct_pair(const std::vector<KeyMatch>& key0s,
                                                               const std::vector<KeyMatch>& keyns)
    {
        for (const auto& k0 : key0s)
            for (const auto& kn : keyns)
                if (k0.candidate->key != kn.candidate->key)
                    return std::make_pair(k0, kn);

        return {};
    }

    // File offset -> "0x<va>" using the packed file's section table, for log output.
    std::string describe_offset(const Bytes& data, std::size_t off)
    {
        try {
            const View v(data);
            const auto nt = std::size_t(v.d(0x3c));
            const std::size_t sections = v.w(nt + 6), table = nt + 24 + v.w(nt + 20);
            const U64 base = v.q(nt + 24 + 0x18);
            for (std::size_t k = 0; k < sections; ++k) {
                const std::size_t s = table + k * 40;
                const U32 rva = v.d(s + 12), raw_size = v.d(s + 16), raw_offset = v.d(s + 20);
                if (off >= raw_offset && off - raw_offset < raw_size)
                    return "0x" + hex(base + rva + (off - raw_offset));
            }
        } catch (const FormatError&) {
        }

        return "0x" + hex(off) + " (file)";
    }

    // Recovers KEY0 (validated against record 0) and KEYN (record 1) from the packer stub.
    Keys extract_keys(const Bytes& data, const std::vector<Row>& rows)
    {
        const KeyCandidates candidates = find_key_candidates(data);
        std::cout << "key candidates: " << candidates.before_call.size() << " pre-call runs, "
                  << candidates.between_calls.size() << " bracketed runs\n";

        auto key0s = keys_decoding(candidates.before_call, data, rows[0]);
        auto keyns = keys_decoding(candidates.between_calls, data, rows[1]);
        auto pair = distinct_pair(key0s, keyns);
        if (!pair) {
            // The stub may build the keys in the opposite order.
            const auto key0s_between = keys_decoding(candidates.between_calls, data, rows[0]);
            const auto keyns_before = keys_decoding(candidates.before_call, data, rows[1]);
            key0s.insert(key0s.end(), key0s_between.begin(), key0s_between.end());
            keyns.insert(keyns.end(), keyns_before.begin(), keyns_before.end());
            pair = distinct_pair(key0s, keyns);
        }

        if (!pair)
            throw FormatError("no distinct KEY0/KEYN pair decrypts the records - key construction changed?");

        auto report = [&](const char* name, const KeyMatch& m, int row) {
            std::cout << "  " << name << " " << hex_bytes(m.candidate->key) << " (xor call @"
                      << describe_offset(data, m.candidate->first_call);
            if (m.candidate->second_call)
                std::cout << ".." << describe_offset(data, *m.candidate->second_call);

            std::cout << "; row" << row << " chain: " << m.regions << " regions)\n";
        };
        report("KEY0", pair->first, 0);
        report("KEYN", pair->second, 1);

        const Key& key0 = pair->first.candidate->key;
        const Key& keyn = pair->second.candidate->key;
        return { Bytes(key0.begin(), key0.end()), Bytes(keyn.begin(), keyn.end()) };
    }

    // Keys come from the input itself when possible; the key file is the fallback.
    Keys resolve_keys(const Bytes& data, const std::vector<Row>& rows, const fs::path& key_file)
    {
        try {
            return extract_keys(data, rows);
        } catch (const FormatError& e) {
            std::cout << "[warn] key extraction failed: " << e.what() << "\n"
                      << "[warn] falling back to " << key_file.string() << '\n';
        }

        return load_keys(key_file);
    }

    // ---- Stages 2/3: XOR layers, framed regions and LZSS -----------------------------------------

    // Region frame: u32 compressed size, u32 decompressed size, u32 crc, then the body XORed with
    // the little-endian bytes of (comp ^ decomp ^ crc).
    struct Region {
        U32 decomp_size;
        Bytes body;
    };

    struct RegionChain {
        std::vector<Region> regions;
        std::size_t consumed = 0;
    };

    RegionChain split_regions(const Bytes& buf)
    {
        RegionChain chain;
        const View v(buf);
        std::size_t& off = chain.consumed;
        while (buf.size() - off >= 12) {
            const U32 comp = v.d(off), decomp = v.d(off + 4), crc = v.d(off + 8);
            if (!comp || comp > buf.size() - off - 12)
                break;

            Bytes key(4);
            put(key, 0, comp ^ decomp ^ crc, 4);
            Bytes body = slice(buf, off + 12, comp);
            xor_in_place(body, key);
            chain.regions.push_back({ decomp, std::move(body) });
            off += 12 + comp;
        }
        return chain;
    }

    // ncguard LZSS: LSB-first bit stream over an 8 KiB zero-initialized window.
    //   0, 8 bits             literal byte
    //   1, 4 bits, 13 bits    copy (len + 3) bytes from window[pos - dist]; len 15 ends the stream
    Bytes lzss_decompress(const Bytes& in, U32 expected_size)
    {
        constexpr std::size_t kWindow = 0x2000, kMask = kWindow - 1;
        Bytes out;
        out.reserve(std::min<U64>(expected_size, U64(in.size()) * 8));   // LZSS expands < 8x
        std::array<Byte, kWindow> window{};
        std::size_t ip = 0;
        U32 acc = 0;
        unsigned bits = 0;

        auto read_bits = [&](unsigned n) {
            while (bits < n) {
                if (ip >= in.size())
                    throw FormatError("lzss out of input");

                acc |= U32(in[ip++]) << bits;
                bits += 8;
            }
            const U32 value = acc & ((U32(1) << n) - 1);
            acc >>= n;
            bits -= n;
            return value;
        };
        auto emit = [&](Byte b) {
            window[out.size() & kMask] = b;
            out.push_back(b);
        };

        for (;;) {
            if (read_bits(1) == 0) {
                emit(static_cast<Byte>(read_bits(8)));
                continue;
            }

            const U32 len = read_bits(4) + 3;
            if (len == 18)
                break;

            std::size_t src = (out.size() - read_bits(13)) & kMask;
            for (U32 j = 0; j < len; ++j, src = (src + 1) & kMask)
                emit(window[src]);
        }
        if (out.size() != expected_size)
            std::cout << "    [warn] lzss len " << hex(out.size()) << " != header " << hex(expected_size) << '\n';

        return out;
    }

    // Decrypts and decompresses one record payload into its regions.
    std::vector<Bytes> decode_record(Bytes payload, const Bytes& key, std::size_t idx)
    {
        xor_in_place(payload, key);
        const RegionChain chain = split_regions(payload);
        if (chain.regions.empty() || chain.consumed < payload.size() / 2)
            throw FormatError("rec" + std::to_string(idx) + ": layer-2 chain consumed " + hex(chain.consumed) + "/" +
                              hex(payload.size()) + " bytes - wrong KEY0/KEYN for this ncguard build?");

        payload = {};   // regions hold their own copies

        std::vector<Bytes> decoded;
        for (std::size_t j = 0; j < chain.regions.size(); ++j) {
            const auto& region = chain.regions[j];
            try {
                decoded.push_back(lzss_decompress(region.body, region.decomp_size));
            } catch (const FormatError& e) {
                std::cout << "    [warn] region " << j << " lzss: " << e.what() << '\n';
                decoded.emplace_back();
            }
        }
        return decoded;
    }

    // ---- Stage 4: module images ------------------------------------------------------------------

    struct Section {
        U32 rva, vsize, chars;
        Bytes body;
    };
    using Sections = std::vector<Section>;

    struct Module {
        std::size_t idx;
        Sections sections;
        Bytes dir_stream;

        U64 weight() const
        {
            U64 n = 0;
            for (const auto& s : sections)
                n += s.vsize;
            return n;
        }
    };

    U32 image_size(const Sections& sections)
    {
        U64 size = 0;
        for (const auto& s : sections)
            size = std::max(size, align_up(U64(s.rva) + s.vsize, kSectionAlign));
        return u32(size);
    }

    // Region 0 of a module record is its directory stream; every later region is a section with a
    // 12-byte (rva, vsize, characteristics) header. Records that don't decode to at least three
    // ascending, non-overlapping sections are not modules.
    std::optional<Module> extract_module(std::size_t idx, std::vector<Bytes>& regions)
    {
        Sections sections;
        for (std::size_t j = 1; j < regions.size(); ++j) {
            Bytes& r = regions[j];
            if (r.size() < 12)
                break;

            const View v(r);
            const U32 rva = v.d(0), vsize = v.d(4), chars = v.d(8);
            if (rva % kSectionAlign || (chars & kScnShared))
                break;

            r.erase(r.begin(), r.begin() + 12);
            sections.push_back({ rva, vsize, chars, std::move(r) });
        }
        if (sections.size() < 3)
            return {};

        for (std::size_t k = 0; k + 1 < sections.size(); ++k)
            if (U64(sections[k].rva) + align_up(sections[k].vsize, kSectionAlign) > sections[k + 1].rva)
                return {};

        return Module{ idx, std::move(sections), std::move(regions[0]) };
    }

    Bytes assemble_image(const Module& m)
    {
        Bytes image(image_size(m.sections));
        for (const auto& s : m.sections)
            copy_range(image, s.rva, s.body, 0, s.body.size());
        return image;
    }

    // ---- Stage 5: data directories and entry point -----------------------------------------------

    struct Directory {
        U32 rva, size;
    };
    using Directories = std::map<int, Directory>;

    // (rva, size) pairs follow a 0x1e-byte header at unknown positions: accept any plausible pair,
    // otherwise resync one byte at a time.
    std::vector<Directory> parse_dir_stream(const Bytes& d)
    {
        std::vector<Directory> entries;
        const View v(d);
        for (std::size_t p = 0x1e; p + 8 <= d.size();) {
            const U32 rva = v.d(p), size = v.d(p + 4);
            if (rva >= 0x1000 && rva < 0x10000000 && size > 0 && size < 0x2000000) {
                entries.push_back({ rva, size });
                p += 8;
            } else {
                ++p;
            }
        }
        return entries;
    }

    struct ImportDescriptor {
        U32 original_first_thunk, name, first_thunk;
        bool is_null() const
        {
            return !original_first_thunk && !name && !first_thunk;
        }
    };

    ImportDescriptor read_import(const View& v, std::size_t off)
    {
        v.require(off, 20);
        return { v.d(off), v.d(off + 12), v.d(off + 16) };
    }

    constexpr int kNoSlot = -1;

    struct Classification {
        int slot;
        std::string what;
    };
    using Match = std::optional<Classification>;

    // One directory-stream entry under test, plus image facts the classifiers share.
    struct Candidate {
        const Bytes& image;
        View b;                       // at least 0x100 bytes at rva, clamped to the image
        U32 rva, size;
        U64 base;
        U32 soi;
        std::optional<U32> iat_rva;   // lowest FirstThunk of the import table, once recognized

        bool in_image(U64 va) const
        {
            return va > base && va - base < soi;
        }
    };

    Match as_pdata(const Candidate& c)
    {
        const U32 n = c.size / 12;
        if (n <= 0x10)
            return {};

        const U32 count = std::min<U32>(n, 64);
        U32 ascending = 0, nonempty = 0;
        for (U32 i = 0; i < count; ++i) {
            const U32 begin = c.b.d(i * 12), end = c.b.d(i * 12 + 4);
            if (begin < end)
                ++nonempty;

            if (i + 1 < count && begin < c.b.d((i + 1) * 12))
                ++ascending;
        }
        if (ascending * 10 > count * 9 && nonempty == count)
            return Classification{ dir::Exception, ".pdata (" + std::to_string(n) + " fns)" };

        return {};
    }

    Match as_basereloc(const Candidate& c)
    {
        if (c.size <= 16)
            return {};

        const U32 page = c.b.d(0), block = c.b.d(4);
        if (page >= c.soi || block < 8 || block > 0x10000 || block % 4 || block > c.size)
            return {};

        U64 off = 0;
        unsigned blocks = 0;
        while (off + 8 <= c.size && blocks < 0x2000) {
            const U32 block_size = c.b.d(std::size_t(off) + 4);
            if (block_size < 8 || off + block_size > c.size)
                break;

            ++blocks;
            off += block_size;
        }
        if (blocks >= 4)
            return Classification{ dir::BaseReloc, "basereloc (" + std::to_string(blocks) + " blocks)" };

        return {};
    }

    Match as_load_config(const Candidate& c)
    {
        if (c.size < 0x60)
            return {};

        const U32 struct_size = c.b.d(0);
        const U64 cookie = c.b.q(kLoadConfigCookie);
        if (std::find(kLoadConfigSizes.begin(), kLoadConfigSizes.end(), struct_size) == kLoadConfigSizes.end() ||
            !c.in_image(cookie))
            return {};

        return Classification{ dir::LoadConfig,
                               "loadcfg (size " + hex(struct_size) + " cookie " + hex(cookie - c.base) + ")" };
    }

    Match as_tls(const Candidate& c)
    {
        const U64 raw_start = c.b.q(0), raw_end = c.b.q(8), index = c.b.q(16), callbacks = c.b.q(24);
        if (c.in_image(raw_start) && raw_start < raw_end && c.in_image(raw_end) && c.in_image(index) &&
            c.in_image(callbacks))
            return Classification{ dir::Tls, "tls (raw " + hex(raw_start - c.base) + "-" + hex(raw_end - c.base) + ")" };

        return {};
    }

    Match as_delay_import(const Candidate& c)
    {
        c.b.require(0, 32);   // ImgDelayDescr
        if (c.b.d(0) != 1 || c.b.d(4) >= c.soi || c.b.d(12) >= c.soi)
            return {};

        const auto name = cstring(c.image, c.b.d(4));
        if (ends_with_ci(name, ".dll"))
            return Classification{ dir::DelayImport, "delayimp (" + name + ")" };

        return {};
    }

    Match as_debug(const Candidate& c)
    {
        const U32 entries = std::max<U32>(1, c.size / 28);
        for (U32 k = 0; k < entries; ++k)
            if (c.b.d(std::size_t(k) * 28 + 12) > 32)
                return {};

        if (c.size % 28 == 0 && has_rsds_signature(c.image, c.b.d(20)))
            return Classification{ dir::Debug, "debug (RSDS)" };

        return {};
    }

    Match as_import(const Candidate& c)
    {
        int dlls = 0;
        for (;; ++dlls) {
            const auto desc = read_import(c.b, std::size_t(dlls) * 20);
            if (desc.is_null())
                break;

            if (desc.original_first_thunk >= c.soi || desc.name >= c.soi || desc.first_thunk >= c.soi)
                return {};

            if (dlls >= 512)
                return {};
        }
        if (dlls < 4)
            return {};

        const auto name = cstring(c.image, c.b.d(12));
        if (ends_with_ci(name, ".dll") || ends_with_ci(name, ".exe"))
            return Classification{ dir::Import, "import (" + std::to_string(dlls) + " dlls)" };

        return {};
    }

    Match as_resource(const Candidate& c)
    {
        const U32 entries = U32(c.b.w(12)) + c.b.w(14);
        if (c.b.d(0) || c.b.d(4) || c.b.w(8) > 16 || c.b.w(10) > 16 || entries == 0 || entries > 0x400)
            return {};

        U32 subdirs = 0;
        for (U32 e = 0; e < entries; ++e) {
            const U32 target = c.b.d(16 + std::size_t(e) * 8 + 4);
            if ((target & 0x80000000u) && (target & 0x7fffffffu) < c.size)
                ++subdirs;
        }
        if (subdirs >= entries / 2)
            return Classification{ dir::Resource, "rsrc" };

        return {};
    }

    Match as_export(const Candidate& c)
    {
        const U32 name = c.b.d(12), functions = c.b.d(20), names = c.b.d(24), names_rva = c.b.d(32);
        if (name == 0 || name >= c.soi || functions == 0 || functions >= 0x100000 || functions != names ||
            names_rva == 0 || names_rva >= c.soi)
            return {};

        const auto dll = cstring(c.image, name);
        if (ends_with_ci(dll, ".exe") || ends_with_ci(dll, ".dll"))
            return Classification{ dir::Export, "export (" + std::to_string(functions) + " names)" };

        return {};
    }

    Match as_iat(const Candidate& c)
    {
        if (c.size % 8 || c.size < 16)
            return {};

        if (c.iat_rva && c.rva == *c.iat_rva)
            return Classification{ dir::Iat, "iat (" + std::to_string(c.size / 8) + " thunks)" };

        const U64 first = c.b.q(0), last = c.b.q(c.size - 8);
        if (first == 0 || first >= c.soi || last != 0)
            return {};

        U32 nonzero = 0;
        for (U32 off = 0; off < std::min<U32>(c.size, 0x100); off += 8)
            if (c.b.q(off))
                ++nonzero;

        if (nonzero > c.size / 16)
            return Classification{ dir::Iat, "iat (heuristic)" };

        return {};
    }

    Classification classify(const Bytes& image, Directory d, U64 base, U32 soi, std::optional<U32> iat_rva)
    {
        constexpr Match (*kClassifiers[])(const Candidate&) = {
            as_pdata, as_basereloc, as_load_config, as_tls, as_delay_import,
            as_debug, as_import, as_resource, as_export, as_iat };
        const Candidate c{ image, View(image, d.rva, std::max<std::size_t>(d.size, 0x100)), d.rva, d.size, base, soi, iat_rva };
        try {
            for (auto classifier : kClassifiers)
                if (auto m = classifier(c))
                    return *m;

            return { kNoSlot, "unrecognized" };
        } catch (const FormatError&) {
            return { kNoSlot, "malformed" };
        }
    }

    std::optional<U32> lowest_first_thunk(const Bytes& image, Directory imports)
    {
        const View v(image);
        std::optional<U32> lowest;
        for (U32 k = 0; k < imports.size / 20; ++k) {
            const auto desc = read_import(v, std::size_t(imports.rva) + std::size_t(k) * 20);
            if (desc.is_null())
                break;

            if (desc.first_thunk && (!lowest || desc.first_thunk < *lowest))
                lowest = desc.first_thunk;
        }
        return lowest;
    }

    Directories recover_directories(const Bytes& image, const std::vector<Directory>& entries, U64 base, U32 soi)
    {
        Directories dirs;
        std::optional<U32> iat_rva;
        for (const auto& entry : entries) {
            const auto c = classify(image, entry, base, soi, iat_rva);
            std::cout << "    " << hex(entry.rva) << " " << hex(entry.size) << " slot "
                      << (c.slot == kNoSlot ? "None" : std::to_string(c.slot)) << " " << c.what << '\n';
            if (c.slot == kNoSlot)
                continue;

            if (dirs.count(c.slot))
                std::cout << "    [warn] duplicate slot " << c.slot << '\n';

            dirs[c.slot] = entry;
            if (c.slot == dir::Import)
                iat_rva = lowest_first_thunk(image, entry);
        }
        dirs[dir::Security] = { 0, 0 };
        return dirs;
    }

    // .pdata RUNTIME_FUNCTION table: 12-byte entries sorted by BeginAddress.
    struct FunctionTable {
        std::vector<U32> begins, ends;

        FunctionTable(const Bytes& image, U32 rva, U32 size)
        {
            const View pd(image, rva, size);
            for (std::size_t i = 0; i < pd.count / 12; ++i) {
                begins.push_back(pd.d(i * 12));
                ends.push_back(pd.d(i * 12 + 4));
            }
        }

        // Index of the last function beginning at or before `addr`.
        std::optional<std::size_t> at_or_before(U32 addr) const
        {
            const auto it = std::upper_bound(begins.begin(), begins.end(), addr);
            if (it == begins.begin())
                return {};

            return static_cast<std::size_t>(it - begins.begin() - 1);
        }
    };

    // Finds instructions in code sections that match `opcode` and whose trailing rel32 operand
    // (the last 4 of `length` bytes) resolves to `target`.
    template <class OpcodeMatch>
    std::vector<U32> find_rel32_refs(const Bytes& image, const Sections& secs, std::size_t length,
                                     std::int64_t target, OpcodeMatch opcode)
    {
        std::vector<U32> hits;
        for (const auto& s : secs) {
            if (!(s.chars & kScnCode))
                continue;

            const View body(image, s.rva, s.vsize);
            const Byte* code = body.data();
            for (std::size_t i = 0; i + length < body.count; ++i) {
                if (!opcode(code + i))
                    continue;

                const std::int64_t next = std::int64_t(s.rva) + std::int64_t(i + length);
                if (next + load_i32(code + i + length - 4) == target)
                    hits.push_back(u32(U64(s.rva) + i));
            }
        }
        return hits;
    }

    struct EntryPoint {
        std::optional<U32> rva;
        std::string note;
    };

    // __security_init_cookie is the only code that stores to the load-config cookie, and its single
    // caller is the CRT entry point.
    EntryPoint derive_entry_point(const Bytes& image, U64 base, const Directories& dirs, const Sections& secs)
    {
        const auto loadcfg = dirs.find(dir::LoadConfig), pdata = dirs.find(dir::Exception);
        if (loadcfg == dirs.end() || pdata == dirs.end())
            return { {}, "need LOADCFG + EXCEPTION dirs" };

        const U64 cookie = View(image).q(std::size_t(loadcfg->second.rva) + kLoadConfigCookie);
        if (cookie < base)
            return { {}, "cookie VA below image base" };

        const FunctionTable fns(image, pdata->second.rva, pdata->second.size);

        // mov [rip+disp32], r64  (REX.W 89 /r with mod=00 rm=101)
        const auto writers = find_rel32_refs(image, secs, 7, std::int64_t(cookie - base), [](const Byte* p) {
            return (p[0] & 0xf8) == 0x48 && p[1] == 0x89 && (p[2] & 0xc7) == 0x05;
        });
        if (writers.size() != 1)
            return { {}, "cookie writers found: " + std::to_string(writers.size()) + " (want 1)" };

        const U32 writer = writers[0];
        const auto wi = fns.at_or_before(writer);
        if (!wi)
            return { {}, "writer " + hex(writer) + " not in .pdata" };

        const U32 init_begin = fns.begins[*wi], init_end = fns.ends[*wi];
        if (writer >= init_end)
            return { {}, "writer " + hex(writer) + " not inside function [" + hex(init_begin) + "," + hex(init_end) + ")" };

        // call rel32
        const auto callers = find_rel32_refs(image, secs, 5, init_begin, [](const Byte* p) { return p[0] == 0xe8; });
        if (callers.empty())
            return { {}, "no E8 callers of cookie fn " + hex(init_begin) };

        const U32 caller = callers.back();
        const auto ci = fns.at_or_before(caller);
        if (!ci)
            return { {}, "caller not in .pdata" };

        const U32 ep_begin = fns.begins[*ci], ep_end = fns.ends[*ci];
        if (caller >= ep_end)
            return { {}, "caller not inside a .pdata function" };

        return { ep_begin, "EP " + hex(ep_begin) + " (fn [" + hex(ep_begin) + "," + hex(ep_end) + "), cookie fn [" +
                               hex(init_begin) + "," + hex(init_end) + "), caller " + hex(caller) + ", " +
                               std::to_string(callers.size()) + " xrefs)" };
    }

    // ---- Stage 6: rebuild the PE -----------------------------------------------------------------

    struct PackedHeaders {
        Bytes raw;              // first kPackedHeaderSize bytes of the packed file
        std::size_t coff, opt;  // offsets of IMAGE_FILE_HEADER and IMAGE_OPTIONAL_HEADER64
        U64 base;
    };

    PackedHeaders parse_packed_headers(const Bytes& data)
    {
        PackedHeaders h{ slice(data, 0, kPackedHeaderSize), 0, 0, 0 };
        const View p(h.raw);
        if (p.w(0) != 0x5a4d)
            throw FormatError("input has no MZ signature");

        const auto nt = std::size_t(p.d(0x3c));
        if (p.d(nt) != 0x4550 || p.w(nt + 4) != 0x8664 || p.w(nt + 24) != 0x20b)
            throw FormatError("expected an AMD64 PE32+ executable");

        h.coff = nt + 4;
        h.opt = nt + 24;
        p.require(h.opt, 0x70);
        h.base = p.q(h.opt + 0x18);
        return h;
    }

    // Synthesized header layout.
    constexpr std::size_t kNtHeaders = 0x80;
    constexpr std::size_t kFileHeader = kNtHeaders + 4;
    constexpr std::size_t kOptHeader = kFileHeader + 20;
    constexpr std::size_t kOptHeaderSize = 0xf0;
    constexpr std::size_t kSectionTable = kOptHeader + kOptHeaderSize;
    constexpr std::size_t kSectionHeaderSize = 40;

    // Recovers plausible section names from flags and the directories each section holds.
    struct SectionNamer {
        const Directories& dirs;
        unsigned rdata = 0, data = 0;
        bool tls_named = false;

        std::string operator()(const Section& s)
        {
            if (s.chars & kScnCode)
                return ".text";

            if (holds(s, dir::Exception))
                return ".pdata";

            if (holds(s, dir::Resource))
                return ".rsrc";

            if (holds(s, dir::BaseReloc))
                return ".reloc";

            if (s.chars & kScnWrite) {
                if (!tls_named && s.vsize >= 0x40 && s.vsize < 0x1000) {
                    tls_named = true;
                    return ".tls";
                }

                return numbered(".data", data);
            }

            return numbered(".rdata", rdata);
        }

    private:
        bool holds(const Section& s, int slot) const
        {
            const auto it = dirs.find(slot);
            if (it == dirs.end() || !it->second.rva)
                return false;

            const U32 rva = it->second.rva;
            return s.rva <= rva && rva < U64(s.rva) + align_up(s.vsize, kSectionAlign);
        }
        static std::string numbered(const std::string& name, unsigned& n)
        {
            return ++n == 1 ? name : name + std::to_string(n);
        }
    };

    // Writes a fresh header over the first kHeaderSize bytes of `image`, copying version, subsystem
    // and stack/heap fields from the packed file. Sections keep RVA == file offset.
    Bytes build_pe(Bytes image, const Sections& secs, const PackedHeaders& packed, std::optional<U32> ep,
                   const Directories& dirs)
    {
        if (secs.empty())
            throw FormatError("no sections");

        if (secs.size() > (kHeaderSize - kSectionTable) / kSectionHeaderSize)
            throw FormatError("section table exceeds the 0x400-byte header");

        if (image.size() < kHeaderSize)
            image.resize(kHeaderSize);

        std::fill_n(image.begin(), kHeaderSize, Byte(0));

        auto copy_field = [&](std::size_t to, std::size_t from, std::size_t n) {
            copy_range(image, to, packed.raw, from, n);
        };

        // DOS header and NT signature.
        image[0] = 'M';
        image[1] = 'Z';
        put(image, 0x3c, kNtHeaders, 4);
        image[kNtHeaders] = 'P';
        image[kNtHeaders + 1] = 'E';

        // IMAGE_FILE_HEADER
        const std::size_t f = kFileHeader;
        put(image, f + 0, 0x8664, 2);                  // Machine: AMD64
        put(image, f + 2, secs.size(), 2);             // NumberOfSections
        copy_field(f + 4, packed.coff + 4, 4);         // TimeDateStamp
        put(image, f + 16, kOptHeaderSize, 2);         // SizeOfOptionalHeader
        copy_field(f + 18, packed.coff + 18, 2);       // Characteristics

        // IMAGE_OPTIONAL_HEADER64
        U64 code = 0, idata = 0;
        for (const auto& s : secs) {
            if (s.chars & kScnCode)
                code += align_up(s.vsize, kFileAlign);
            else if (s.chars & kScnInitData)
                idata += align_up(s.vsize, kFileAlign);
        }
        const std::size_t o = kOptHeader;
        put(image, o + 0x00, 0x20b, 2);                // Magic: PE32+
        copy_field(o + 0x02, packed.opt + 0x02, 2);    // linker version
        put(image, o + 0x04, u32(code), 4);            // SizeOfCode
        put(image, o + 0x08, u32(idata), 4);           // SizeOfInitializedData
        put(image, o + 0x10, ep.value_or(0), 4);       // AddressOfEntryPoint
        put(image, o + 0x14, secs[0].rva, 4);          // BaseOfCode
        put(image, o + 0x18, packed.base, 8);          // ImageBase
        put(image, o + 0x20, kSectionAlign, 4);        // SectionAlignment
        put(image, o + 0x24, kFileAlign, 4);           // FileAlignment
        copy_field(o + 0x28, packed.opt + 0x28, 16);   // OS/image/subsystem versions, Win32VersionValue
        put(image, o + 0x38, image_size(secs), 4);     // SizeOfImage
        put(image, o + 0x3c, kHeaderSize, 4);          // SizeOfHeaders
        copy_field(o + 0x44, packed.opt + 0x44, 4);    // Subsystem, DllCharacteristics
        copy_field(o + 0x48, packed.opt + 0x48, 32);   // stack/heap reserve and commit
        copy_field(o + 0x6c, packed.opt + 0x6c, 4);    // NumberOfRvaAndSizes
        for (const auto& [slot, d] : dirs) {
            put(image, o + 0x70 + std::size_t(slot) * 8, d.rva, 4);
            put(image, o + 0x74 + std::size_t(slot) * 8, d.size, 4);
        }

        // Section table.
        SectionNamer name_of{ dirs };
        for (std::size_t k = 0; k < secs.size(); ++k) {
            const auto& s = secs[k];
            const std::size_t h = kSectionTable + k * kSectionHeaderSize;
            const std::string name = name_of(s);
            std::copy_n(name.begin(), std::min<std::size_t>(8, name.size()), image.begin() + h);
            put(image, h + 8, s.vsize, 4);                              // VirtualSize
            put(image, h + 12, s.rva, 4);                               // VirtualAddress
            put(image, h + 16, u32(align_up(s.vsize, kFileAlign)), 4);  // SizeOfRawData
            put(image, h + 20, s.rva, 4);                               // PointerToRawData
            put(image, h + 36, s.chars, 4);                             // Characteristics
        }
        return image;
    }

    // FileVersion ("a.b.c.d") from the VS_FIXEDFILEINFO in a rebuilt PE's RT_VERSION resource.
    std::optional<std::string> file_version(const Bytes& pe)
    {
        constexpr U32 kRtVersion = 16, kSubdirFlag = 0x80000000u, kFixedInfoSignature = 0xfeef04bd;
        try {
            const View b(pe);
            const auto opt = std::size_t(b.d(0x3c)) + 24;
            const U32 rsrc = b.d(opt + 0x70 + std::size_t(dir::Resource) * 8);
            if (!rsrc)
                return {};

            U32 node = 0;
            for (int level = 0; level < 3; ++level) {
                const std::size_t table = std::size_t(rsrc) + node;
                const U32 entries = U32(b.w(table + 12)) + b.w(table + 14);
                std::optional<U32> target;
                for (U32 e = 0; e < entries && !target; ++e) {
                    const std::size_t entry = table + 16 + std::size_t(e) * 8;
                    if (level == 0 && b.d(entry) != kRtVersion)
                        continue;

                    target = b.d(entry + 4);
                }
                const bool expect_subdir = level < 2;
                if (!target || bool(*target & kSubdirFlag) != expect_subdir)
                    return {};

                node = *target & ~kSubdirFlag;
            }
            const std::size_t data_entry = std::size_t(rsrc) + node;
            const View info(pe, b.d(data_entry), b.d(data_entry + 4));

            // VS_VERSIONINFO puts VS_FIXEDFILEINFO (52 bytes, DWORD aligned) after its key string.
            for (std::size_t off = 0; off + 52 <= info.count; off += 4) {
                if (info.d(off) != kFixedInfoSignature)
                    continue;

                const U32 ms = info.d(off + 8), ls = info.d(off + 12);
                return std::to_string(ms >> 16) + "." + std::to_string(ms & 0xffff) + "." +
                       std::to_string(ls >> 16) + "." + std::to_string(ls & 0xffff);
            }
            return {};
        } catch (const FormatError&) {
            return {};
        }
    }

    // ---- Reporting -------------------------------------------------------------------------------

    std::string join(std::span<const std::string> names)
    {
        std::string out;
        for (std::size_t i = 0; i < names.size(); ++i)
            out += (i ? ", " : "") + names[i];
        return out;
    }

    // Prints the count plus the first three and last two names.
    void print_names(const char* label, const std::vector<std::string>& names)
    {
        const std::span<const std::string> all(names);
        std::cout << "  [chk] " << label << ": " << names.size() << ": [" << join(all.first(std::min<std::size_t>(3, all.size()))) << "]";
        if (names.size() > 3)
            std::cout << " ... [" << join(all.last(2)) << "]";

        std::cout << '\n';
    }

    void print_records(const std::vector<Row>& rows)
    {
        std::cout << "records table: " << rows.size() << " rows\n";
        for (std::size_t i = 0; i < rows.size(); ++i) {
            const auto& r = rows[i];
            std::cout << "  [" << i << "] tag " << unsigned(r.tag) << " ptr " << hex(r.ptr) << " len " << hex(r.len)
                      << " meta " << hex_bytes(r.meta) << " name " << std::quoted(r.name) << '\n';
        }
    }

    // Reads the rebuilt PE back and prints what its headers point at.
    void verify_output(const Bytes& pe, U64 base)
    {
        const View b(pe);
        const auto nt = std::size_t(b.d(0x3c)), opt = nt + 24;
        const U32 ep = b.d(opt + 0x10), soi = b.d(opt + 0x38);
        std::cout << "  [chk] EP " << hex(ep) << " SizeOfImage " << hex(soi) << " nsec " << b.w(nt + 6) << '\n';
        auto dir_rva = [&](int slot) { return b.d(opt + 0x70 + std::size_t(slot) * 8); };
        auto dir_size = [&](int slot) { return b.d(opt + 0x74 + std::size_t(slot) * 8); };

        if (const U32 rva = dir_rva(dir::Import)) {
            std::vector<std::string> names;
            for (std::size_t off = rva;; off += 20) {
                const auto desc = read_import(b, off);
                if (desc.is_null())
                    break;

                names.push_back(cstring(pe, desc.name, 64));
            }
            print_names("IMPORT", names);
        }

        if (const U32 rva = dir_rva(dir::DelayImport)) {
            std::vector<std::string> names;
            for (std::size_t off = rva; b.d(off); off += 32)
                names.push_back(cstring(pe, b.d(off + 4), 64));
            print_names("DELAYIMP", names);
        }

        if (const U32 rva = dir_rva(dir::Debug)) {
            const U32 type = b.d(std::size_t(rva) + 12), data = b.d(std::size_t(rva) + 20);
            if (has_rsds_signature(pe, data))
                std::cout << "  [chk] DEBUG[0] type " << type << ": " << cstring(pe, u32(U64(data) + 24), 64) << '\n';
        }

        if (const U32 rva = dir_rva(dir::Tls)) {
            std::cout << "  [chk] TLS raw " << hex(b.q(rva) - base) << "-" << hex(b.q(std::size_t(rva) + 8) - base)
                      << " idx " << hex(b.q(std::size_t(rva) + 16) - base) << '\n';
        }

        if (const U32 rva = dir_rva(dir::LoadConfig))
            std::cout << "  [chk] LOADCFG cookie rva " << hex(b.q(std::size_t(rva) + kLoadConfigCookie) - base) << '\n';

        if (const U32 rva = dir_rva(dir::Exception); rva && ep) {
            const FunctionTable fns(pe, rva, dir_size(dir::Exception) & ~U32(7));
            if (const auto j = fns.at_or_before(ep)) {
                const U32 next = *j + 1 < fns.begins.size() ? fns.begins[*j + 1] : 0;
                std::cout << "  [chk] .pdata: EP in function [" << hex(fns.begins[*j]) << ", " << hex(next) << ")\n";
            } else {
                std::cout << "  [warn] EP not covered by .pdata\n";
            }
        }
    }

    // ---- Driver ----------------------------------------------------------------------------------

    std::string rec_tag(std::size_t idx)
    {
        return "  [rec" + std::to_string(idx) + "] ";
    }

    std::optional<Module> unpack_record(const Bytes& data, const Row& r, std::size_t idx, const Keys& keys)
    {
        const std::string tag = rec_tag(idx);
        const U64 off = U64(r.ptr) + kPayloadDelta;
        if (off > data.size() || r.len > data.size() - off) {
            std::cout << tag << "payload " << hex(off) << "+" << hex(r.len) << " out of range, skipped\n";
            return {};
        }

        const bool first = idx == 0;
        std::cout << tag << "payload @" << hex(off) << " len " << hex(r.len) << " key " << (first ? "KEY0" : "KEYN")
                  << " name " << std::quoted(r.name) << '\n';
        auto regions = decode_record(slice(data, host_size(off), r.len), first ? keys.key0 : keys.keyn, idx);

        std::size_t nonempty = 0, total = 0;
        for (const auto& region : regions) {
            if (!region.empty())
                ++nonempty;

            total += region.size();
        }
        std::cout << tag << nonempty << " regions, " << hex(r.len) << " -> " << hex(total) << " bytes decoded\n";

        auto mod = extract_module(idx, regions);
        if (mod)
            std::cout << tag << "MODULE: " << mod->sections.size() << " sections, SizeOfImage "
                      << hex(image_size(mod->sections)) << '\n';

        return mod;
    }

    // Writes the rebuilt PE to `outdir` as "<stem>_<file version>.exe".
    void rebuild_main_module(const Module& mod, const PackedHeaders& packed, const fs::path& outdir, const std::string& stem)
    {
        Bytes image = assemble_image(mod);
        const std::string tag = rec_tag(mod.idx);
        const auto entries = parse_dir_stream(mod.dir_stream);
        std::cout << tag << "MAIN module: dir stream " << mod.dir_stream.size() << " bytes\n"
                  << tag << "dir stream: " << entries.size() << " nonzero entries\n";
        const Directories dirs = recover_directories(image, entries, packed.base, u32(image.size()));

        std::string missing;
        for (int slot : { dir::Export, dir::Import, dir::Resource, dir::Exception, dir::BaseReloc, dir::Debug,
                          dir::Tls, dir::LoadConfig, dir::Iat, dir::DelayImport })
            if (!dirs.count(slot))
                missing += std::string(" ") + kDirNames[slot];

        if (!missing.empty())
            std::cout << tag << "[warn] dirs not recovered:" << missing << '\n';

        const auto ep = derive_entry_point(image, packed.base, dirs, mod.sections);
        std::cout << tag << ep.note << '\n';

        const Bytes pe = build_pe(std::move(image), mod.sections, packed, ep.rva, dirs);
        const auto version = file_version(pe);
        if (!version)
            std::cout << tag << "[warn] no VS_VERSION_INFO resource, naming output _unpacked\n";

        const auto out_path = outdir / (stem + "_" + version.value_or("unpacked") + ".exe");
        write_file(out_path, pe);
        std::cout << "wrote " << out_path.string() << " (" << hex(pe.size()) << " bytes)\n";
        verify_output(pe, packed.base);
    }

    int run(int argc, char** argv)
    {
        if (argc < 2 || argc > 3) {
            std::cout << "Usage: unpack <packed.exe> [outdir]\n"
                         "Default outdir: directory containing the unpacker executable.\n"
                         "XOR keys are extracted from the input; if that fails they are read from "
                      << kKeysFile << " next to the unpacker executable.\n";
            return 2;
        }

        const fs::path exe_dir = fs::absolute(argv[0]).parent_path();
        const fs::path path = fs::absolute(argv[1]);
        const fs::path outdir = argc > 2 ? fs::absolute(argv[2]) : exe_dir;
        fs::create_directories(outdir);

        const Bytes data = read_file(path);
        const PackedHeaders packed = parse_packed_headers(data);
        std::cout << "packed: " << path.string() << " (" << hex(data.size()) << " bytes)\n";

        const auto rows = find_records_table(data);
        print_records(rows);

        const Keys keys = resolve_keys(data, rows, exe_dir / kKeysFile);

        std::vector<Module> modules;
        for (std::size_t i = 0; i < rows.size(); ++i)
            if (auto mod = unpack_record(data, rows[i], i, keys))
                modules.push_back(std::move(*mod));

        if (modules.empty())
            throw FormatError("no module records identified");

        const auto& main_module = *std::max_element(modules.begin(), modules.end(), [](const Module& a, const Module& b) {
            return a.weight() < b.weight();
        });
        rebuild_main_module(main_module, packed, outdir, path.stem().string());
        return 0;
    }
}

int main(int argc, char** argv)
{
    try {
        return ncg::run(argc, argv);
    } catch (const std::exception& e) {
        std::cerr << "FATAL: " << e.what() << '\n';
        return 1;
    }
}
