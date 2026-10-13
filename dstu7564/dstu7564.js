/*
 * Copyright (c) 2020 Illya Petrov <ilya.muromec@gmail.com>.
 * Original C version copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>.
 * Derived from dstu7564 1.1.0; distributed under BSD-2-Clause.
 */

const ROWS = 8;
const NB_512 = 8;
const NB_1024 = 16;
const STATE_BYTE_SIZE_512 = 64;
const STATE_BYTE_SIZE_1024 = 128;
const NR_512 = 10;
const NR_1024 = 14;
const MAX_BLOCK_LEN = 64;

const tables = require('./subrowcol').map((bytes) => {
  const words = new Uint32Array(bytes.length / 4);
  for (let i = 0; i < words.length; i++) words[i] = bytes.readUInt32LE(i * 4);
  return words;
});

function permute(ctx, bytes, isQ) {
  const columns = ctx.columns;
  let state = new Uint32Array(columns * 2);
  let output = new Uint32Array(columns * 2);
  for (let i = 0; i < state.length; i++) state[i] = bytes.readUInt32LE(i * 4);

  for (let round = 0; round < ctx.rounds; round++) {
    for (let col = 0; col < columns; col++) {
      const at = col * 2;
      if (isQ) {
        // Add the 64-bit Q constant as two exact 32-bit words with carry.
        const sum = state[at] + 0xf0f0f0f3;
        const high = (0x00f0f0f0 | (((columns - col - 1) << 4) ^ round) << 24) >>> 0;
        state[at] = sum >>> 0;
        state[at + 1] = (state[at + 1] + high + (sum > 0xffffffff ? 1 : 0)) >>> 0;
      } else {
        state[at] ^= (col << 4) ^ round;
      }
    }

    for (let col = 0; col < columns; col++) {
      let lo = 0;
      let hi = 0;
      for (let row = 0; row < ROWS; row++) {
        const shift = columns === NB_1024 && row === 7 ? 11 : row;
        const src = ((col - shift) & (columns - 1)) * 2 + (row >>> 2);
        const byte = (state[src] >>> ((row & 3) * 8)) & 0xff;
        lo ^= ctx.p_boxrowcol[row][byte * 2];
        hi ^= ctx.p_boxrowcol[row][byte * 2 + 1];
      }
      output[col * 2] = lo;
      output[col * 2 + 1] = hi;
    }
    const tmp = state;
    state = output;
    output = tmp;
  }
  for (let i = 0; i < state.length; i++) bytes.writeUInt32LE(state[i], i * 4);
}

function P(ctx, bytes) {
  permute(ctx, bytes, false);
}

function Q(ctx, bytes) {
  permute(ctx, bytes, true);
}

function dstu7564_alloc(sbox_id) {
  if (sbox_id !== 0) throw new Error('Wrong sbox id');
  return {
    state: Buffer.alloc(STATE_BYTE_SIZE_1024),
    p_boxrowcol: tables.map((row) => new Uint32Array(row)),
    last_block: Buffer.alloc(STATE_BYTE_SIZE_1024 * 2),
    is_inited: false,
  };
}

function mod(num, divisor) {
  return ((num % divisor) + divisor) % divisor;
}

function padding(buf, buf_len_out, buf_len_out_bit, nbytes) {
  let zero_nbytes;
  let cur_pos;
  let i;

  cur_pos = buf_len_out % nbytes;
  zero_nbytes = mod(-buf_len_out_bit - 97, nbytes << 3) >>> 3;

  buf[cur_pos] = 0x80;
  cur_pos++;
  buf.fill(0, cur_pos, cur_pos + zero_nbytes);
  cur_pos += zero_nbytes;

  for (i = 0; i < 96 >> 3; ++i, ++cur_pos) {
    if (i < 4) {
      buf[cur_pos] = (buf_len_out_bit >> (i << 3)) & 0xff;
    } else {
      buf[cur_pos] = 0;
    }
  }
}

function dstu7564_xor(arg1, arg2, out, columns) {
  const limit =
    columns === NB_1024 ? STATE_BYTE_SIZE_1024 : STATE_BYTE_SIZE_512;
  for (let idx = 0; idx < limit; idx++) {
    out[idx] = arg1[idx] ^ arg2[idx];
  }
}

function digest(ctx, data) {
  let temp1 = Buffer.alloc(NB_1024 * ROWS);
  let temp2 = Buffer.alloc(NB_1024 * ROWS);

  data.copy(temp2, 0, 0, ctx.columns << 3);
  dstu7564_xor(ctx.state, data, temp1, ctx.columns);
  P(ctx, temp1);
  Q(ctx, temp2);

  dstu7564_xor(temp1, temp2, temp2, ctx.columns);
  dstu7564_xor(ctx.state, temp2, ctx.state, ctx.columns);
}

function output_transformation(ctx, hash) {
  let temp = Buffer.alloc(NB_1024 * ROWS);
  let ret = 0;

  ctx.state.copy(temp, 0, 0, ROWS * NB_1024);

  P(ctx, temp);

  dstu7564_xor(ctx.state, temp, ctx.state, ctx.columns);

  ctx.state.copy(hash, 0, ctx.nbytes - ctx.hash_nbytes, ctx.nbytes);
  dstu7564_init(ctx, ctx.hash_nbytes);

  return ret;
}

function CHECK_PARAM(param) {
  if (!param) {
    throw new Error("param is expected to be set");
  }
}

function SET_ERROR(code) {
  throw new Error("Code " + code);
}

function dstu7564_init(ctx, hash_nbytes) {
  CHECK_PARAM(ctx);
  CHECK_PARAM((hash_nbytes > 0) & (hash_nbytes <= 64));

  if (hash_nbytes <= 32) {
    ctx.rounds = NR_512;
    ctx.columns = NB_512;
    ctx.nbytes = STATE_BYTE_SIZE_512;
    ctx.state.fill(0, 0, STATE_BYTE_SIZE_512);
    ctx.state[0] = STATE_BYTE_SIZE_512;
  } else {
    ctx.rounds = NR_1024;
    ctx.columns = NB_1024;
    ctx.nbytes = STATE_BYTE_SIZE_1024;
    ctx.state.fill(0, 0, STATE_BYTE_SIZE_1024);
    ctx.state[0] = STATE_BYTE_SIZE_1024;
  }
  ctx.hash_nbytes = hash_nbytes;

  ctx.last_block_el = 0;
  ctx.msg_tot_len = 0;
  ctx.is_inited = true;
}

function dstu7564_update(ctx, data_buf, data_buf_len) {
  let block_size;

  CHECK_PARAM(ctx);
  CHECK_PARAM(data_buf);
  CHECK_PARAM(data_buf_len >= 0);

  if (ctx.is_inited == false) {
    SET_ERROR(-1);
  }

  block_size = ctx.nbytes;

  ctx.msg_tot_len += data_buf_len << 3;
  if (ctx.last_block_el + data_buf_len < block_size) {
    data_buf.copy(ctx.last_block, ctx.last_block_el, 0, data_buf_len);
    ctx.last_block_el += data_buf_len;
    return true;
  }

  data_buf.copy(
    ctx.last_block,
    ctx.last_block_el,
    0,
    block_size - ctx.last_block_el
  );
  digest(ctx, ctx.last_block);
  ctx.last_block.fill(0, 0, MAX_BLOCK_LEN);

  let shift = block_size - ctx.last_block_el;
  data_buf_len -= block_size - ctx.last_block_el;
  let i;
  for (i = 0; i + block_size <= data_buf_len; i += block_size) {
    digest(ctx, data_buf.slice(shift + i));
  }

  ctx.last_block_el = data_buf_len - i;
  if (ctx.last_block_el != 0) {
    data_buf.copy(ctx.last_block, 0, shift + i, shift + i + ctx.last_block_el);
  }
}

function dstu7564_final(ctx, hash) {
  CHECK_PARAM(ctx);
  CHECK_PARAM(hash);
  if (ctx.is_inited == false) {
    SET_ERROR(-1);
  }

  var cur_pos = ctx.last_block_el % ctx.nbytes;
  var zero_nbytes = mod(-ctx.msg_tot_len - 97, ctx.nbytes << 3) >>> 3;
  var total_padded = ctx.last_block_el + 1 + zero_nbytes + 12;

  padding(ctx.last_block, ctx.last_block_el, ctx.msg_tot_len, ctx.nbytes);
  digest(ctx, ctx.last_block);

  if (total_padded > ctx.nbytes) {
    ctx.last_block.copy(ctx.last_block, 0, ctx.nbytes, total_padded);
    ctx.last_block.fill(0, total_padded - ctx.nbytes, ctx.nbytes);
    digest(ctx, ctx.last_block);
  }

  output_transformation(ctx, hash);
}

function computeHash(size, buffer) {
  const hash = Buffer.alloc(size);
  const ctx = dstu7564_alloc(0);
  dstu7564_init(ctx, size);
  dstu7564_update(ctx, buffer, buffer.length);
  dstu7564_final(ctx, hash);
  return hash;
}

function padBlock(buf, blockSize) {
  const msgLenBits = buf.length * 8;
  const zeroNbytes = ((blockSize * 8) - ((msgLenBits + 97) % (blockSize * 8))) >>> 3;
  const padded = Buffer.alloc(buf.length + 1 + zeroNbytes + 12);
  buf.copy(padded);
  let pos = buf.length;
  padded[pos++] = 0x80;
  pos += zeroNbytes;
  for (let i = 0; i < 12; i++) {
    padded[pos++] = i < 4 ? (msgLenBits >> (i * 8)) & 0xff : 0;
  }
  return padded;
}

function invertKey(key) {
  const out = Buffer.from(key);
  for (let i = 0; i < out.length; i++) out[i] = ~out[i] & 0xff;
  return out;
}

function computeKmac(key, msg, macLen) {
  if (macLen !== 32 && macLen !== 48 && macLen !== 64) {
    throw new Error("Invalid MAC length " + macLen);
  }
  const blockSize = macLen <= 32 ? 64 : 128; // 32->512-bit state, 48/64->1024-bit state
  const padK = padBlock(key, blockSize);
  const padM = padBlock(msg, blockSize);
  const invK = invertKey(key);

  const ctx = dstu7564_alloc(0);
  dstu7564_init(ctx, macLen);
  dstu7564_update(ctx, padK, padK.length);
  dstu7564_update(ctx, padM, padM.length);
  dstu7564_update(ctx, invK, invK.length);
  const hash = Buffer.alloc(macLen);
  dstu7564_final(ctx, hash);
  return hash;
}

function dstu7564_kmac(key, macLen) {
  if (macLen !== 32 && macLen !== 48 && macLen !== 64) {
    throw new Error("Invalid MAC length " + macLen);
  }
  const blockSize = macLen <= 32 ? 64 : 128;
  const padK = padBlock(key, blockSize);
  const invK = invertKey(key);

  const ctx = dstu7564_alloc(0);
  dstu7564_init(ctx, macLen);
  dstu7564_update(ctx, padK, padK.length);
  const keyedState = Buffer.from(ctx.state.subarray(0, blockSize));
  const keyedMsgTotLen = ctx.msg_tot_len;
  const keyedLastBlockEl = ctx.last_block_el;

  function compute(msg) {
    ctx.state.fill(0, 0, blockSize);
    keyedState.copy(ctx.state, 0);
    ctx.msg_tot_len = keyedMsgTotLen;
    ctx.last_block_el = keyedLastBlockEl;
    ctx.last_block.fill(0, 0, blockSize);
    ctx.is_inited = true;

    const padM = padBlock(msg, blockSize);
    dstu7564_update(ctx, padM, padM.length);
    dstu7564_update(ctx, invK, invK.length);
    const hash = Buffer.alloc(macLen);
    dstu7564_final(ctx, hash);
    return hash;
  }

  return { compute };
}

module.exports = {
  computeHash,
  computeKmac,
  dstu7564_kmac,
  dstu7564_alloc,
  dstu7564_init,
  dstu7564_update,
  dstu7564_final,
};

