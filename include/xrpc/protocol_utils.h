#ifndef XRPC_PROTOCOL_UTILS_H
#define XRPC_PROTOCOL_UTILS_H

/*
 * Note: byte order is NOT modified by these helpers.
 */

#include <stdint.h>

/*
 * ---------------------------
 * Constants: shifts and masks
 * ---------------------------
 */

/*
 * Request preamble fields (packed into a preamble byte):
 *  bits 0-3 : TYPE  (4 bits)
 *  bits 4-7 : VER   (4 bits)
 */
enum {
  XRPC_REQ_TYPE_SHIFT = 0,
  XRPC_REQ_TYPE_MASK = 0x0Fu,
  XRPC_REQ_VER_SHIFT = 4,
  XRPC_REQ_VER_MASK = 0x0Fu
};

/*
 * Response preamble fields (packed into a preamble byte):
 *  bits 0-3 : TYPE  (4 bits)
 *  bits 4-7 : VER   (4 bits)
 */
enum {
  XRPC_RES_TYPE_SHIFT = 0,
  XRPC_RES_TYPE_MASK = 0x0Fu,
  XRPC_RES_VER_SHIFT = 4,
  XRPC_RES_VER_MASK = 0x0Fu
};

/*
 * Request frame opinfo bit layout (MSB..LSB):
 *  bits  1-0 : DC (2 bits)
 *  bits  5-2 : DTYPB (4 bits)
 *  bits  9-6 : SCALE (4 bits)
 *  bits 15-10: OPCODE (6 bits)
 */
enum {
  XRPC_REQ_FR_DTYPC_SHIFT = 0,
  XRPC_REQ_FR_DTYPC_MASK = 0x03u, /* 2 bits */

  XRPC_REQ_FR_DTYPB_SHIFT = 2,
  XRPC_REQ_FR_DTYPB_MASK = 0x0Fu, /* 4 bits */

  XRPC_REQ_FR_SCALE_SHIFT = 6,
  XRPC_REQ_FR_SCALE_MASK = 0x0Fu, /* 4 bits */

  XRPC_REQ_FR_OPCODE_SHIFT = 10,
  XRPC_REQ_FR_OPCODE_MASK = 0x3Fu /* 6 bits */
};

/*
 * Response frame opinfo bit layout (MSB..LSB):
 *  bits  1-0 : DC (2 bits)
 *  bits  5-2 : DTYPB (4 bits)
 *  bits  9-6 : SCALE (4 bits)
 *  bits 15-10: STATUS (6 bits)
 */
enum {
  XRPC_RES_FR_DTYPC_SHIFT = 0,
  XRPC_RES_FR_DTYPC_MASK = 0x03u,

  XRPC_RES_FR_DTYPB_SHIFT = 2,
  XRPC_RES_FR_DTYPB_MASK = 0x0Fu,

  XRPC_RES_FR_SCALE_SHIFT = 6,
  XRPC_RES_FR_SCALE_MASK = 0x0Fu,

  XRPC_RES_FR_STATUS_SHIFT = 10,
  XRPC_RES_FR_STATUS_MASK = 0x3Fu
};

/*
 * ---------------------------
 * Request: word-level helpers
 * Word1: [preamble:8][resp_mode:8][batch_id:16]
 * Word2: [batch_size:16][reserved:16]
 * ---------------------------
 */

static inline uint32_t xrpc_req_word1_pack(uint8_t preamble_byte,
                                           uint8_t resp_mode,
                                           uint16_t batch_id) {
  return ((uint32_t)preamble_byte << 24) | ((uint32_t)resp_mode << 16) |
         ((uint32_t)batch_id);
}

static inline uint8_t xrpc_req_word1_preamble(uint32_t word1) {
  return (uint8_t)(word1 >> 24);
}

static inline uint8_t xrpc_req_word1_respmode(uint32_t word1) {
  return (uint8_t)((word1 >> 16) & 0xFFu);
}

static inline uint16_t xrpc_req_word1_batchid(uint32_t word1) {
  return (uint16_t)(word1 & 0xFFFFu);
}

static inline uint32_t xrpc_req_word2_pack(uint16_t batch_size,
                                           uint16_t reserved) {
  return ((uint32_t)batch_size << 16) | (uint32_t)reserved;
}

static inline uint16_t xrpc_req_word2_batchsize(uint32_t word2) {
  return (uint16_t)((word2 >> 16) & 0xFFFFu);
}

static inline uint16_t xrpc_req_word2_reserved(uint32_t word2) {
  return (uint16_t)(word2 & 0xFFFFu);
}

/*
 * ---------------------------
 * Request: preamble helpers
 * ---------------------------
 */

static inline uint8_t xrpc_req_get_type_from_preamble(uint8_t preamble) {
  return (uint8_t)((preamble >> XRPC_REQ_TYPE_SHIFT) & XRPC_REQ_TYPE_MASK);
}

static inline uint8_t xrpc_req_get_ver_from_preamble(uint8_t preamble) {
  return (uint8_t)((preamble >> XRPC_REQ_VER_SHIFT) & XRPC_REQ_VER_MASK);
}

static inline void xrpc_req_set_version(uint8_t *preamble_ptr,
                                        uint8_t version) {
  uint8_t v = *preamble_ptr;
  v &= (uint8_t) ~((uint8_t)XRPC_REQ_VER_MASK << XRPC_REQ_VER_SHIFT);
  v |= (uint8_t)(((uint8_t)version & XRPC_REQ_VER_MASK) << XRPC_REQ_VER_SHIFT);
  *preamble_ptr = v;
}

static inline void xrpc_req_set_type(uint8_t *preamble_ptr, uint8_t type) {
  uint8_t v = *preamble_ptr;
  v &= (uint8_t) ~((uint8_t)XRPC_REQ_TYPE_MASK << XRPC_REQ_TYPE_SHIFT);
  v |= (uint8_t)(((uint8_t)type & XRPC_REQ_TYPE_MASK) << XRPC_REQ_TYPE_SHIFT);
  *preamble_ptr = v;
}

/*
 * ---------------------------
 * Response: word-level helpers
 * Word1: [preamble:8][reserved/resp-mode:8][batch_id:16]
 * Word2: [status:16][payload_size:16]
 * ---------------------------
 */

static inline uint32_t xrpc_res_word1_pack(uint8_t preamble_byte,
                                           uint16_t batch_id) {
  return ((uint32_t)preamble_byte << 24) | ((uint32_t)0u << 16) |
         ((uint32_t)batch_id);
}

static inline uint8_t xrpc_res_word1_preamble(uint32_t word1) {
  return (uint8_t)(word1 >> 24);
}

static inline uint8_t xrpc_res_word1_respmode(uint32_t word1) {
  return (uint8_t)((word1 >> 16) & 0xFFu);
}

static inline uint16_t xrpc_res_word1_batchid(uint32_t word1) {
  return (uint16_t)(word1 & 0xFFFFu);
}

static inline uint32_t xrpc_res_word2_pack(uint16_t status,
                                           uint16_t payload_size) {
  return ((uint32_t)status << 16) | (uint32_t)payload_size;
}

static inline uint16_t xrpc_res_word2_status(uint32_t word2) {
  return (uint16_t)((word2 >> 16) & 0xFFFFu);
}

static inline uint16_t xrpc_res_word2_payload_size(uint32_t word2) {
  return (uint16_t)(word2 & 0xFFFFu);
}

/*
 * ---------------------------
 * Response: preamble helpers
 * ---------------------------
 */

static inline uint8_t xrpc_res_get_type_from_preamble(uint8_t preamble) {
  return (uint8_t)((preamble >> XRPC_RES_TYPE_SHIFT) & XRPC_RES_TYPE_MASK);
}

static inline uint8_t xrpc_res_get_ver_from_preamble(uint8_t preamble) {
  return (uint8_t)((preamble >> XRPC_RES_VER_SHIFT) & XRPC_RES_VER_MASK);
}

static inline void xrpc_res_set_version(uint8_t *preamble_ptr,
                                        uint8_t version) {
  uint8_t v = *preamble_ptr;
  v &= (uint8_t) ~((uint8_t)XRPC_RES_VER_MASK << XRPC_RES_VER_SHIFT);
  v |= (uint8_t)(((uint8_t)version & XRPC_RES_VER_MASK) << XRPC_RES_VER_SHIFT);
  *preamble_ptr = v;
}

static inline void xrpc_res_set_type(uint8_t *preamble_ptr, uint8_t type) {
  uint8_t v = *preamble_ptr;
  v &= (uint8_t) ~((uint8_t)XRPC_RES_TYPE_MASK << XRPC_RES_TYPE_SHIFT);
  v |= (uint8_t)(((uint8_t)type & XRPC_RES_TYPE_MASK) << XRPC_RES_TYPE_SHIFT);
  *preamble_ptr = v;
}

/*
 * ---------------------------
 * Request frame helpers (word-level)
 * Word1: [opinfo:16][size_params:16]
 * Word2: [batch_id:16][frame_id:16]
 * ---------------------------
 */

static inline uint32_t xrpc_req_fr_word1_pack(uint16_t opinfo,
                                              uint16_t size_params) {
  return ((uint32_t)opinfo << 16) | (uint32_t)size_params;
}

static inline uint32_t xrpc_req_fr_word2_pack(uint16_t batch_id,
                                              uint16_t frame_id) {
  return ((uint32_t)batch_id << 16) | (uint32_t)frame_id;
}

static inline uint16_t xrpc_req_fr_word1_opinfo(uint32_t word1) {
  return (uint16_t)((word1 >> 16) & 0xFFFFu);
}

static inline uint16_t xrpc_req_fr_word1_size_params(uint32_t word1) {
  return (uint16_t)(word1 & 0xFFFFu);
}

static inline uint16_t xrpc_req_fr_word2_batch_id(uint32_t word2) {
  return (uint16_t)((word2 >> 16) & 0xFFFFu);
}

static inline uint16_t xrpc_req_fr_word2_frame_id(uint32_t word2) {
  return (uint16_t)(word2 & 0xFFFFu);
}

/* Opinfo getters (take 16-bit opinfo) */
static inline uint8_t xrpc_req_fr_get_dtypc_from_opinfo(uint16_t opinfo) {
  return (uint8_t)((opinfo >> XRPC_REQ_FR_DTYPC_SHIFT) &
                   XRPC_REQ_FR_DTYPC_MASK);
}

static inline uint8_t xrpc_req_fr_get_dtypb_from_opinfo(uint16_t opinfo) {
  return (uint8_t)((opinfo >> XRPC_REQ_FR_DTYPB_SHIFT) &
                   XRPC_REQ_FR_DTYPB_MASK);
}

static inline uint8_t xrpc_req_fr_get_scale_from_opinfo(uint16_t opinfo) {
  return (uint8_t)((opinfo >> XRPC_REQ_FR_SCALE_SHIFT) &
                   XRPC_REQ_FR_SCALE_MASK);
}

static inline uint8_t xrpc_req_fr_get_opcode_from_opinfo(uint16_t opinfo) {
  return (uint8_t)((opinfo >> XRPC_REQ_FR_OPCODE_SHIFT) &
                   XRPC_REQ_FR_OPCODE_MASK);
}

/* Opinfo setters operate on pointer to uint16_t (avoid double-evaluation) */
static inline void xrpc_req_fr_set_dtypc(uint16_t *opinfo_ptr, uint8_t dtypc) {
  uint16_t v = *opinfo_ptr;
  v &=
      (uint16_t) ~((uint16_t)XRPC_REQ_FR_DTYPC_MASK << XRPC_REQ_FR_DTYPC_SHIFT);
  v |= (uint16_t)(((uint16_t)dtypc & XRPC_REQ_FR_DTYPC_MASK)
                  << XRPC_REQ_FR_DTYPC_SHIFT);
  *opinfo_ptr = v;
}

static inline void xrpc_req_fr_set_dtypb(uint16_t *opinfo_ptr, uint8_t dtypb) {
  uint16_t v = *opinfo_ptr;
  v &=
      (uint16_t) ~((uint16_t)XRPC_REQ_FR_DTYPB_MASK << XRPC_REQ_FR_DTYPB_SHIFT);
  v |= (uint16_t)(((uint16_t)dtypb & XRPC_REQ_FR_DTYPB_MASK)
                  << XRPC_REQ_FR_DTYPB_SHIFT);
  *opinfo_ptr = v;
}

static inline void xrpc_req_fr_set_scale(uint16_t *opinfo_ptr, uint8_t scale) {
  uint16_t v = *opinfo_ptr;
  v &=
      (uint16_t) ~((uint16_t)XRPC_REQ_FR_SCALE_MASK << XRPC_REQ_FR_SCALE_SHIFT);
  v |= (uint16_t)(((uint16_t)scale & XRPC_REQ_FR_SCALE_MASK)
                  << XRPC_REQ_FR_SCALE_SHIFT);
  *opinfo_ptr = v;
}

static inline void xrpc_req_fr_set_opcode(uint16_t *opinfo_ptr,
                                          uint8_t opcode) {
  uint16_t v = *opinfo_ptr;
  v &= (uint16_t) ~((uint16_t)XRPC_REQ_FR_OPCODE_MASK
                    << XRPC_REQ_FR_OPCODE_SHIFT);
  v |= (uint16_t)(((uint16_t)opcode & XRPC_REQ_FR_OPCODE_MASK)
                  << XRPC_REQ_FR_OPCODE_SHIFT);
  *opinfo_ptr = v;
}

/*
 * ---------------------------
 * Response frame helpers (word-level)
 * Word1: [opinfo:16][size_params:16]
 * Word2: [batch_id:16][frame_id:16]
 * ---------------------------
 */

static inline uint32_t xrpc_res_fr_word1_pack(uint16_t opinfo,
                                              uint16_t size_params) {
  return ((uint32_t)opinfo << 16) | (uint32_t)size_params;
}

static inline uint32_t xrpc_res_fr_word2_pack(uint16_t batch_id,
                                              uint16_t frame_id) {
  return ((uint32_t)batch_id << 16) | (uint32_t)frame_id;
}

static inline uint16_t xrpc_res_fr_word1_opinfo(uint32_t word1) {
  return (uint16_t)((word1 >> 16) & 0xFFFFu);
}

static inline uint16_t xrpc_res_fr_word1_size_params(uint32_t word1) {
  return (uint16_t)(word1 & 0xFFFFu);
}

static inline uint16_t xrpc_res_fr_word2_batch_id(uint32_t word2) {
  return (uint16_t)((word2 >> 16) & 0xFFFFu);
}

static inline uint16_t xrpc_res_fr_word2_frame_id(uint32_t word2) {
  return (uint16_t)(word2 & 0xFFFFu);
}

/* Response opinfo getters */
static inline uint8_t xrpc_res_fr_get_dtypc_from_opinfo(uint16_t opinfo) {
  return (uint8_t)((opinfo >> XRPC_RES_FR_DTYPC_SHIFT) &
                   XRPC_RES_FR_DTYPC_MASK);
}

static inline uint8_t xrpc_res_fr_get_dtypb_from_opinfo(uint16_t opinfo) {
  return (uint8_t)((opinfo >> XRPC_RES_FR_DTYPB_SHIFT) &
                   XRPC_RES_FR_DTYPB_MASK);
}

static inline uint8_t xrpc_res_fr_get_scale_from_opinfo(uint16_t opinfo) {
  return (uint8_t)((opinfo >> XRPC_RES_FR_SCALE_SHIFT) &
                   XRPC_RES_FR_SCALE_MASK);
}

static inline uint8_t xrpc_res_fr_get_status_from_opinfo(uint16_t opinfo) {
  return (uint8_t)((opinfo >> XRPC_RES_FR_STATUS_SHIFT) &
                   XRPC_RES_FR_STATUS_MASK);
}

/* Response opinfo setters */
static inline void xrpc_res_fr_set_dtypc(uint16_t *opinfo_ptr, uint8_t dtypc) {
  uint16_t v = *opinfo_ptr;
  v &=
      (uint16_t) ~((uint16_t)XRPC_RES_FR_DTYPC_MASK << XRPC_RES_FR_DTYPC_SHIFT);
  v |= (uint16_t)(((uint16_t)dtypc & XRPC_RES_FR_DTYPC_MASK)
                  << XRPC_RES_FR_DTYPC_SHIFT);
  *opinfo_ptr = v;
}

static inline void xrpc_res_fr_set_dtypb(uint16_t *opinfo_ptr, uint8_t dtypb) {
  uint16_t v = *opinfo_ptr;
  v &=
      (uint16_t) ~((uint16_t)XRPC_RES_FR_DTYPB_MASK << XRPC_RES_FR_DTYPB_SHIFT);
  v |= (uint16_t)(((uint16_t)dtypb & XRPC_RES_FR_DTYPB_MASK)
                  << XRPC_RES_FR_DTYPB_SHIFT);
  *opinfo_ptr = v;
}

static inline void xrpc_res_fr_set_scale(uint16_t *opinfo_ptr, uint8_t scale) {
  uint16_t v = *opinfo_ptr;
  v &=
      (uint16_t) ~((uint16_t)XRPC_RES_FR_SCALE_MASK << XRPC_RES_FR_SCALE_SHIFT);
  v |= (uint16_t)(((uint16_t)scale & XRPC_RES_FR_SCALE_MASK)
                  << XRPC_RES_FR_SCALE_SHIFT);
  *opinfo_ptr = v;
}

static inline void xrpc_res_fr_set_status(uint16_t *opinfo_ptr,
                                          uint8_t status) {
  uint16_t v = *opinfo_ptr;
  v &= (uint16_t) ~((uint16_t)XRPC_RES_FR_STATUS_MASK
                    << XRPC_RES_FR_STATUS_SHIFT);
  v |= (uint16_t)(((uint16_t)status & XRPC_RES_FR_STATUS_MASK)
                  << XRPC_RES_FR_STATUS_SHIFT);
  *opinfo_ptr = v;
}

#endif /* XRPC_PROTOCOL_UTILS_H */
