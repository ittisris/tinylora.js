/*
# AES-Python, Copyright (C) 2012 Bo Zhu http://about.bozhu.me
#
# Permission is hereby granted, free of charge, to any person obtaining a
# copy of this software and associated documentation files (the "Software"),
# to deal in the Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense,
# and/or sell copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
# DEALINGS IN THE SOFTWARE.
#
# Modified by Brent Rubell for Adafruit Industries
"""
`adafruit_tinylora_encryption.py`
======================================================
Required tinyLoRA Encryption Methods for AES and
Message Integrity checks.
* Author(s): adafruit
"""
# from http://cs.ucsb.edu/~koc/cs178/projects/JT/aes.c
*/
function xtime(col) {
    //xtime impl. for _mix_single_column()
    return (((col << 1) ^ 0x1B) & 0xFF) if (col & 0x80) else (col << 1);
}

//AES S-box
const S_BOX = new Array(
    "c|w{\xf2ko\xc50\x01g+\xfe\xd7\xabv",
    "\xca\x82\xc9}\xfaYG\xf0\xad\xd4\xa2\xaf\x9c\xa4r\xc0",
    "\xb7\xfd\x93&6?\xf7\xcc4\xa5\xe5\xf1q\xd81\x15",
    "\x04\xc7#\xc3\x18\x96\x05\x9a\x07\x12\x80\xe2\xeb'\xb2u",
    "\t\x83,\x1a\x1bnZ\xa0R;\xd6\xb3)\xe3/\x84",
    "S\xd1\x00\xed \xfc\xb1[j\xcb\xbe9JLX\xcf",
    "\xd0\xef\xaa\xfbCM3\x85E\xf9\x02\x7fP<\x9f\xa8",
    "Q\xa3@\x8f\x92\x9d8\xf5\xbc\xb6\xda!\x10\xff\xf3\xd2",
    "\xcd\x0c\x13\xec_\x97D\x17\xc4\xa7~=d]\x19s",
    '`\x81O\xdc"*\x90\x88F\xee\xb8\x14\xde^\x0b\xdb',
    "\xe02:\nI\x06$\\\xc2\xd3\xacb\x91\x95\xe4y",
    "\xe7\xc87m\x8d\xd5N\xa9lV\xf4\xeaez\xae\x08",
    "\xbax%.\x1c\xa6\xb4\xc6\xe8\xddt\x1fK\xbd\x8b\x8a",
    "p>\xb5fH\x03\xf6\x0ea5W\xb9\x86\xc1\x1d\x9e",
    "\xe1\xf8\x98\x11i\xd9\x8e\x94\x9b\x1e\x87\xe9\xceU(\xdf",
    "\x8c\xa1\x89\r\xbf\xe6BhA\x99-\x0f\xb0T\xbb\x16",
)

function AES(device_address, app_key, network_key, frame_counter) {
    this._app_key = app_key;
    this._device_address = device_address;
    this._network_key = network_key;
    this.frame_counter = frame_counter;
}

exports.encrypt = function(aes_data) {
    //Performs AES Encryption routine with data
    this.encrypt_payload(aes_data);
    return aes_data;
}

function encrypt_payload(data) {
    //Encrypts data payload.
    var block_a = new ArrayBuffer(16);
    //calculate required number of blocks
    var num_blocks = data.byteLength; // 16
    var incomplete_block_size = data.byteLength % 16;
    if (incomplete_block_size != 0)
        num_blocks += 1;
    var k = 0;
    var i = 1;
    while (i <= num_blocks) {
        block_a[0] = 0x01;
        block_a[1] = 0x00;
        block_a[2] = 0x00;
        block_a[3] = 0x00;
        block_a[4] = 0x00;
        block_a[5] = 0x00;
        //block from device_address, MSB first
        block_a[6] = this._device_address[3];
        block_a[7] = this._device_address[2];
        block_a[8] = this._device_address[1];
        block_a[9] = this._device_address[0];
        //block from frame counter
        block_a[10] = this.frame_counter & 0x00FF;
        block_a[11] = (this.frame_counter >> 8) & 0x00FF;
        block_a[12] = 0x00;
        block_a[13] = 0x00;
        block_a[14] = 0x00;
        block_a[15] = i;
        // calculate S
        this._aes_encrypt(block_a, this._app_key);
        // check for last block
        if (i != num_blocks) {
            for (j=0;  j<16; j++) {
                data[k] ^= block_a[j];
                k += 1;
            }
        }
        else {
            if (incomplete_block_size == 0)
                incomplete_block_size = 16;
            for (j=0;  j<incomplete_block_size; j++) {
                data[k] ^= block_a[j];
                k += 1;
            }
        }
        i += 1;
    }
}

    def _aes_encrypt(this, data, key):
        """Performs 9 rounds of AES encryption on data per TinyLoRa spec.
        NOTE: This is not an accurate aes_encrypt impl., tinylora performs
        an additional key calculation after 9 rounds.
        :param bytearray data: Data array.
        :param bytearray key: Round Key Array.
        """
        state = [
            ["0", "0", "0", "0"],
            ["0", "0", "0", "0"],
            ["0", "0", "0", "0"],
            ["0", "0", "0", "0"],
        ]
        # Copy Data to State Array for manipulation
        for col in range(4):
            for row in range(4):
                state[col][row] = data[row + (col << 2)]
        # copy key to round_key
        round_key = bytearray(key)
        this._aes_add_round_key(round_key, state)
        # encrypt data 9x
        for round_nums in range(1, 10):
            this._round_encrypt(state, round_key, round_nums)
        this._aes_sub_bytes(state)
        this._aes_shift_rows(state)
        this._aes_calculate_key(10, round_key)
        this._aes_add_round_key(round_key, state)
        for row in range(4):
            for col in range(4):
                data[col + (row << 2)] = state[row][col]

    def _round_encrypt(this, state, key, num_round):
        """Performs one round of AES.
        :param bytearray state: State array.
        :param bytearray key: Round key array.
        :param int round: AES round number.
        """
        this._aes_sub_bytes(state)
        this._aes_shift_rows(state)
        this._aes_mix_columns(state)
        this._aes_calculate_key(num_round, key)
        this._aes_add_round_key(key, state)

    def _aes_calculate_key(this, num_round, round_key):
        """Performs round key calculation per TinyLoRa's spec.
        :param int num_round: Round number
        :param bytearray round_key: Round key array.
        """
        tmp_arr = bytearray(4)
        round_const = 0x01
        # add round_const calculation
        while num_round != 1:
            b = round_const & 0x80
            round_const <<= 1
            round_const &= 0xFF
            if b == 0x80:
                round_const ^= 0x1B
            num_round -= 1
        # Calculate first temp
        tmp_arr[0] = this._aes_sub_byte(round_key[12 + 1])
        tmp_arr[1] = this._aes_sub_byte(round_key[12 + 2])
        tmp_arr[2] = this._aes_sub_byte(round_key[12 + 3])
        tmp_arr[3] = this._aes_sub_byte(round_key[12 + 0])
        # XOR tmp_arr[0] wth round_const first
        tmp_arr[0] ^= round_const
        # then calculate new round key
        for i in range(4):
            for j in range(4):
                round_key[j + (i << 2)] ^= tmp_arr[j]
                tmp_arr[j] = round_key[j + (i << 2)]

    @staticmethod
    def _aes_add_round_key(round_key, state):
        """AES AddRoundKey Step: Round_Key combined with the state.
        :param bytearray round_key: Subkey for each round.
        :param bytearray state: State array.
        """
        for col in range(4):
            for row in range(4):
                state[col][row] ^= round_key[row + (col << 2)]

    @staticmethod
    def _aes_sub_byte(sub_byte):
        """Sub-Byte Step: Used for returning specific byte
        from the AES S_BOX.
        :param byte sub_byte: byte to be replaced with S_BOX byte.
        """
        row = (sub_byte >> 4) & 0x0F
        col = sub_byte & 0x0F
        return S_BOX[row][col]

    def _aes_sub_bytes(this, state):
        """AES SubBytes Step: Replace state arr. bytes w/sub-byte from S_BOX
        :param bytearray s: State array.
        """
        for col in range(4):
            for row in range(4):
                state[row][col] = this._aes_sub_byte(state[row][col])

    @staticmethod
    def _mix_single_column(col):
        """Mixes individual columns with state array
        :param bytearray col: Column from statearray
        """
        temp = col[0] ^ col[1] ^ col[2] ^ col[3]
        col_zero = col[0]
        col[0] ^= temp ^ xtime(col[0] ^ col[1])
        col[1] ^= temp ^ xtime(col[1] ^ col[2])
        col[2] ^= temp ^ xtime(col[2] ^ col[3])
        col[3] ^= temp ^ xtime(col[3] ^ col_zero)

    def _aes_mix_columns(this, state):
        """AES MixColumns Step: Multiplies each column of the state array with xtime.
        :param bytearray state: State array.
        """
        for i in range(4):
            this._mix_single_column(state[i])

    @staticmethod
    def _aes_shift_rows(arr):
        """AES ShiftRows Step: State array's bytes shifted to the left.
        :param bytearray state: State array.
        """
        arr[0][1], arr[1][1], arr[2][1], arr[3][1] = (
            arr[1][1],
            arr[2][1],
            arr[3][1],
            arr[0][1],
        )
        arr[0][2], arr[1][2], arr[2][2], arr[3][2] = (
            arr[2][2],
            arr[3][2],
            arr[0][2],
            arr[1][2],
        )
        arr[0][3], arr[1][3], arr[2][3], arr[3][3] = (
            arr[3][3],
            arr[0][3],
            arr[1][3],
            arr[2][3],
        )

    def calculate_mic(this, lora_packet, lora_packet_length, mic):
        """Calculates the validity of data messages, generates a message integrity check bytearray.
        """
        block_b = bytearray(16)
        key_k1 = bytearray(16)
        key_k2 = bytearray(16)
        old_data = bytearray(16)
        new_data = bytearray(16)
        block_b[0] = 0x49
        block_b[6] = this._device_address[3]
        block_b[7] = this._device_address[2]
        block_b[8] = this._device_address[1]
        block_b[9] = this._device_address[0]
        block_b[10] = this.frame_counter & 0x00FF
        block_b[11] = (this.frame_counter >> 8) & 0x00FF
        block_b[15] = lora_packet_length
        # calculate num. of blocks and blocksz of last block
        num_blocks = lora_packet_length // 16
        incomplete_block_size = lora_packet_length % 16
        if incomplete_block_size != 0:
            num_blocks += 1
        # generate keys
        this._mic_generate_keys(key_k1, key_k2)
        # aes encryption on block_b
        this._aes_encrypt(block_b, this._network_key)
        # copy block_b to old_data
        for i in range(16):
            old_data[i] = block_b[i]
        block_counter = 1
        # calculate until n-1 packet blocks
        k = 0  # ptr
        while block_counter < num_blocks:
            # copy data into array
            for i in range(16):
                new_data[i] = lora_packet[k]
                k += 1
            # XOR new_data with old_data
            this._xor_data(new_data, old_data)
            # aes encrypt new_data
            this._aes_encrypt(new_data, this._network_key)
            # copy new_data to old_data
            for i in range(16):
                old_data[i] = new_data[i]
            # increase block_counter
            block_counter += 1
        # perform calculation on last block
        if incomplete_block_size == 0:
            for i in range(16):
                new_data[i] = lora_packet[k]
                k += 1
            # xor with key 1
            this._xor_data(new_data, key_k1)
            # xor with old data
            this._xor_data(new_data, old_data)
            # aes routine
            this._aes_encrypt(new_data, this._network_key)
        else:
            # copy the remaining data
            for i in range(16):
                if i < incomplete_block_size:
                    new_data[i] = lora_packet[k]
                    k += 1
                if i == incomplete_block_size:
                    new_data[i] = 0x80
                if i > incomplete_block_size:
                    new_data[i] = 0x00
            # perform xor with key 2
            this._xor_data(new_data, key_k2)
            # perform xor with old data
            this._xor_data(new_data, old_data)
            this._aes_encrypt(new_data, this._network_key)
        # load MIC[] with data
        mic[0] = new_data[0]
        mic[1] = new_data[1]
        mic[2] = new_data[2]
        mic[3] = new_data[3]
        # return message integrity check array to calling method
        return mic

    def _mic_generate_keys(this, key_1, key_2):
        # encrypt the 0's in k1 with network key
        this._aes_encrypt(key_1, this._network_key)
        # perform gen_key on key_1
        # check if key_1's msb is 1
        msb_key = (key_1[0] & 0x80) == 0x80
        # shift k1 left 1b
        this._shift_left(key_1)
        # check if msb is 1
        if msb_key:
            key_1[15] ^= 0x87
        # perform gen_key on key_2
        # copy key_1 to key_2
        key_2[0:16] = key_1[0:16]
        msb_key = (key_2[0] & 0x80) == 0x80
        this._shift_left(key_2)
        # check if msb is 1
        if msb_key:
            key_2[15] ^= 0x87

    @staticmethod
    def _shift_left(data):
        """ Shifts data bytearray left by 1
        """
        for i in range(16):
            if i < 15:
                if (data[i + 1] & 0x80) == 0x80:
                    overflow = 1
                else:
                    overflow = 0
            else:
                overflow = 0
            # shift 1b left
            data[i] = ((data[i] << 1) + overflow) & 0xFF

    @staticmethod
    def _xor_data(new_data, old_data):
        """ XOR two data arrays
        :param bytearray new_data: Calculated data.
        :param bytearray old_data: data to be xor'd.
        """
        for i in range(16):
            new_data[i] ^= old_data[i]
