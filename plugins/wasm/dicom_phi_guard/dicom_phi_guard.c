// Reference Wasm Dissector: Blocks DICOM PACS PHI Leakage
#define SENTINEL_VERDICT_PASS        0
#define SENTINEL_VERDICT_KERNEL_DROP 3

// Host Imports
extern void sentinel_host_log(int level, const char* msg);

__attribute__((export_name("sentinel_dissect")))
int sentinel_dissect(const unsigned char* pkt, int len) {
    if (len < 128) return SENTINEL_VERDICT_PASS;

    // Search for DICOM Magic preamble "DICM" at byte offset 128
    if (pkt[128] == 'D' && pkt[129] == 'I' && pkt[130] == 'C' && pkt[131] == 'M') {
        // Tag (0010, 0010) = Patient's Name. If present unencrypted -> Trigger DROP
        for (int i = 132; i < len - 4; ++i) {
            if (pkt[i] == 0x10 && pkt[i+1] == 0x00 && pkt[i+2] == 0x10 && pkt[i+3] == 0x00) {
                return SENTINEL_VERDICT_KERNEL_DROP;
            }
        }
    }
    return SENTINEL_VERDICT_PASS;
}