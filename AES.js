<!DOCTYPE html> 
<html> 
<head> 
<meta http-equiv="Content-Type" content="text/html; charset=utf-8"/> 
<meta name="viewport" content="width=device-width, initial-scale=1.0, minimum-scale=0.5, maximum-scale=2.0, user-scalable=yes" /> 
<title>AES加密和解密</title> 
</head> 
 
<body> 
<script type="text/javascript"> 
        if(typeof FileReader == 'undefined'){ 
            var div=document.getElementById("dd"); 
            div.innerHTML='你的浏览器不支持FileReader接口！'; 
            document.getElementById("file").setAttribute("disabled","disabled"); 
            document.getElementById("filea").setAttribute("disabled","disabled"); 
            document.getElementById("fileb").setAttribute("disabled","disabled"); 
        } 
 
 
         
 
// This is not really a random number generator object, and two SeededRandom 
// objects will conflict with one another, but it's good enough for generating  
// the rsa key. 
function SeededRandom(){} 
 
function SRnextBytes(ba) 
{ 
    var i; 
    for(i = 0; i < ba.length; i++) 
    { 
        ba[i] = Math.floor(Math.random() * 256); 
    } 
} 
 
SeededRandom.prototype.nextBytes = SRnextBytes; 
 
// prng4.js - uses Arcfour as a PRNG 
 
function Arcfour() { 
  this.i = 0; 
  this.j = 0; 
  this.S = new Array(); 
} 
 
// Initialize arcfour context from key, an array of ints, each from [0..255] 
function ARC4init(key) { 
  var i, j, t; 
  for(i = 0; i < 256; ++i) 
    this.S[i] = i; 
  j = 0; 
  for(i = 0; i < 256; ++i) { 
    j = (j + this.S[i] + key[i % key.length]) & 255; 
    t = this.S[i]; 
    this.S[i] = this.S[j]; 
    this.S[j] = t; 
  } 
  this.i = 0; 
  this.j = 0; 
} 
 
function ARC4next() { 
  var t; 
  this.i = (this.i + 1) & 255; 
  this.j = (this.j + this.S[this.i]) & 255; 
  t = this.S[this.i]; 
  this.S[this.i] = this.S[this.j]; 
  this.S[this.j] = t; 
  return this.S[(t + this.S[this.i]) & 255]; 
} 
 
Arcfour.prototype.init = ARC4init; 
Arcfour.prototype.next = ARC4next; 
 
// Plug in your RNG constructor here 
function prng_newstate() { 
  return new Arcfour(); 
} 
 
// Pool size must be a multiple of 4 and greater than 32. 
// An array of bytes the size of the pool will be passed to init() 
var rng_psize = 256; 
 
// Random number generator - requires a PRNG backend, e.g. prng4.js 
 
// For best results, put code like 
// <body onClick='rng_seed_time();' onKeyPress='rng_seed_time();'> 
// in your main HTML document. 
 
var rng_state; 
var rng_pool; 
var rng_pptr; 
 
// Mix in a 32-bit integer into the pool 
function rng_seed_int(x) { 
  rng_pool[rng_pptr++] ^= x & 255; 
  rng_pool[rng_pptr++] ^= (x >> 8) & 255; 
  rng_pool[rng_pptr++] ^= (x >> 16) & 255; 
  rng_pool[rng_pptr++] ^= (x >> 24) & 255; 
  if(rng_pptr >= rng_psize) rng_pptr -= rng_psize; 
} 
 
// Mix in the current time (w/milliseconds) into the pool 
function rng_seed_time() { 
  rng_seed_int(new Date().getTime()); 
} 
 
// Initialize the pool with junk if needed. 
if(rng_pool == null) { 
  rng_pool = new Array(); 
  rng_pptr = 0; 
  var t; 
  while(rng_pptr < rng_psize) {  // extract some randomness from Math.random() 
    t = Math.floor(65536 * Math.random()); 
    rng_pool[rng_pptr++] = t >>> 8; 
    rng_pool[rng_pptr++] = t & 255; 
  } 
  rng_pptr = 0; 
  rng_seed_time(); 
  //rng_seed_int(window.screenX); 
  //rng_seed_int(window.screenY); 
} 
 
function rng_get_byte() { 
  if(rng_state == null) { 
    rng_seed_time(); 
    rng_state = prng_newstate(); 
    rng_state.init(rng_pool); 
    for(rng_pptr = 0; rng_pptr < rng_pool.length; ++rng_pptr) 
      rng_pool[rng_pptr] = 0; 
    rng_pptr = 0; 
    //rng_pool = null; 
  } 
  // TODO: allow reseeding after first request 
  return rng_state.next(); 
} 
 
function rng_get_bytes(ba) { 
  var i; 
  for(i = 0; i < ba.length; ++i) ba[i] = rng_get_byte(); 
} 
 
function SecureRandom() {} 
 
SecureRandom.prototype.nextBytes = rng_get_bytes; 
         
         
var aes = (function () { 
 
    var my = {}; 
 
    my.Sbox = new Array(99, 124, 119, 123, 242, 107, 111, 197, 48, 1, 103, 43, 254, 215, 171, 118, 202, 130, 201, 125, 250, 89, 71, 240, 173, 212, 162, 175, 156, 164, 114, 192, 183, 253, 147, 38, 54, 63, 247, 204, 52, 165, 229, 241, 113, 216, 49, 21, 4, 199, 35, 195, 24, 150, 5, 154, 7, 18, 128, 226, 235, 39, 178, 117, 9, 131, 44, 26, 27, 110, 90, 160, 82, 59, 214, 179, 41, 227, 47, 132, 83, 209, 0, 237, 32, 252, 177, 91, 106, 203, 190, 57, 74, 76, 88, 207, 208, 239, 170, 251, 67, 77, 51, 133, 69, 249, 2, 127, 80, 60, 159, 168, 81, 163, 64, 143, 146, 157, 56, 245, 188, 182, 218, 33, 16, 255, 243, 210, 205, 12, 19, 236, 95, 151, 68, 23, 196, 167, 126, 61, 100, 93, 25, 115, 96, 129, 79, 220, 34, 42, 144, 136, 70, 238, 184, 20, 222, 94, 11, 219, 224, 50, 58, 10, 73, 6, 36, 92, 194, 211, 172, 98, 145, 149, 228, 121, 231, 200, 55, 109, 141, 213, 78, 169, 108, 86, 244, 234, 101, 122, 174, 8, 186, 120, 37, 46, 28, 166, 180, 198, 232, 221, 116, 31, 75, 189, 139, 138, 112, 62, 181, 102, 72, 3, 246, 14, 97, 53, 87, 185, 134, 193, 29, 158, 225, 248, 152, 17, 105, 217, 142, 148, 155, 30, 135, 233, 206, 85, 40, 223, 140, 161, 137, 13, 191, 230, 66, 104, 65, 153, 45, 15, 176, 84, 187, 22); 
 
    my.ShiftRowTab = new Array(0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11); 
 
    my.Init = function () { 
        my.Sbox_Inv = new Array(256); 
        for (var i = 0; i < 256; i++) 
        my.Sbox_Inv[my.Sbox[i]] = i; 
 
        my.ShiftRowTab_Inv = new Array(16); 
        for (var i = 0; i < 16; i++) 
        my.ShiftRowTab_Inv[my.ShiftRowTab[i]] = i; 
 
        my.xtime = new Array(256); 
        for (var i = 0; i < 128; i++) { 
            my.xtime[i] = i << 1; 
            my.xtime[128 + i] = (i << 1) ^ 0x1b; 
        } 
    } 
 
    my.Done = function () { 
        delete my.Sbox_Inv; 
        delete my.ShiftRowTab_Inv; 
        delete my.xtime; 
    } 
 
    my.ExpandKey = function (key) { 
        var kl = key.length, 
            ks, Rcon = 1; 
        switch (kl) { 
        case 16: 
            ks = 16 * (10 + 1); 
            break; 
        case 24: 
            ks = 16 * (12 + 1); 
            break; 
        case 32: 
            ks = 16 * (14 + 1); 
            break; 
        default: 
            alert("my.ExpandKey: Only key lengths of 16, 24 or 32 bytes allowed!"); 
        } 
        for (var i = kl; i < ks; i += 4) { 
            var temp = key.slice(i - 4, i); 
            if (i % kl == 0) { 
                temp = new Array(my.Sbox[temp[1]] ^ Rcon, my.Sbox[temp[2]], my.Sbox[temp[3]], my.Sbox[temp[0]]); 
                if ((Rcon <<= 1) >= 256) Rcon ^= 0x11b; 
            } 
            else if ((kl > 24) && (i % kl == 16)) temp = new Array(my.Sbox[temp[0]], my.Sbox[temp[1]], my.Sbox[temp[2]], my.Sbox[temp[3]]); 
            for (var j = 0; j < 4; j++) 
            key[i + j] = key[i + j - kl] ^ temp[j]; 
        } 
    } 
 
    my.Encrypt = function (block, key) { 
        var l = key.length; 
        my.AddRoundKey(block, key.slice(0, 16)); 
        for (var i = 16; i < l - 16; i += 16) { 
            my.SubBytes(block, my.Sbox); 
            my.ShiftRows(block, my.ShiftRowTab); 
            my.MixColumns(block); 
            my.AddRoundKey(block, key.slice(i, i + 16)); 
        } 
        my.SubBytes(block, my.Sbox); 
        my.ShiftRows(block, my.ShiftRowTab); 
        my.AddRoundKey(block, key.slice(i, l)); 
    } 
 
    my.Decrypt = function (block, key) { 
        var l = key.length; 
        my.AddRoundKey(block, key.slice(l - 16, l)); 
        my.ShiftRows(block, my.ShiftRowTab_Inv); 
        my.SubBytes(block, my.Sbox_Inv); 
        for (var i = l - 32; i >= 16; i -= 16) { 
            my.AddRoundKey(block, key.slice(i, i + 16)); 
            my.MixColumns_Inv(block); 
            my.ShiftRows(block, my.ShiftRowTab_Inv); 
            my.SubBytes(block, my.Sbox_Inv); 
        } 
        my.AddRoundKey(block, key.slice(0, 16)); 
    } 
 
    my.SubBytes = function (state, sbox) { 
        for (var i = 0; i < 16; i++) 
        state[i] = sbox[state[i]]; 
    } 
 
    my.AddRoundKey = function (state, rkey) { 
        for (var i = 0; i < 16; i++) 
        state[i] ^= rkey[i]; 
    } 
 
    my.ShiftRows = function (state, shifttab) { 
        var h = new Array().concat(state); 
        for (var i = 0; i < 16; i++) 
        state[i] = h[shifttab[i]]; 
    } 
 
    my.MixColumns = function (state) { 
        for (var i = 0; i < 16; i += 4) { 
            var s0 = state[i + 0], 
                s1 = state[i + 1]; 
            var s2 = state[i + 2], 
                s3 = state[i + 3]; 
            var h = s0 ^ s1 ^ s2 ^ s3; 
            state[i + 0] ^= h ^ my.xtime[s0 ^ s1]; 
            state[i + 1] ^= h ^ my.xtime[s1 ^ s2]; 
            state[i + 2] ^= h ^ my.xtime[s2 ^ s3]; 
            state[i + 3] ^= h ^ my.xtime[s3 ^ s0]; 
        } 
    } 
 
    my.MixColumns_Inv = function (state) { 
        for (var i = 0; i < 16; i += 4) { 
            var s0 = state[i + 0], 
                s1 = state[i + 1]; 
            var s2 = state[i + 2], 
                s3 = state[i + 3]; 
            var h = s0 ^ s1 ^ s2 ^ s3; 
            var xh = my.xtime[h]; 
            var h1 = my.xtime[my.xtime[xh ^ s0 ^ s2]] ^ h; 
            var h2 = my.xtime[my.xtime[xh ^ s1 ^ s3]] ^ h; 
            state[i + 0] ^= h1 ^ my.xtime[s0 ^ s1]; 
            state[i + 1] ^= h2 ^ my.xtime[s1 ^ s2]; 
            state[i + 2] ^= h1 ^ my.xtime[s2 ^ s3]; 
            state[i + 3] ^= h2 ^ my.xtime[s3 ^ s0]; 
        } 
    } 
 
    return my; 
 
}()); 
var cryptico = (function() { 
 
    var my = {}; 
 
    aes.Init(); 
 
    var base64Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'; 
 
    my.b256to64 = function(t) { 
        var a, c, n; 
        var r = '', l = 0, s = 0; 
        var tl = t.length; 
        for (n = 0; n < tl; n++) 
        { 
            c = t.charCodeAt(n); 
            if (s == 0) 
            { 
                r += base64Chars.charAt((c >> 2) & 63); 
                a = (c & 3) << 4; 
            } 
            else if (s == 1) 
            { 
                r += base64Chars.charAt((a | (c >> 4) & 15)); 
                a = (c & 15) << 2; 
            } 
            else if (s == 2) 
            { 
                r += base64Chars.charAt(a | ((c >> 6) & 3)); 
                l += 1; 
                r += base64Chars.charAt(c & 63); 
            } 
            l += 1; 
            s += 1; 
            if (s == 3) s = 0; 
        } 
        if (s > 0) 
        { 
            r += base64Chars.charAt(a); 
            l += 1; 
            r += '='; 
            l += 1; 
        } 
        if (s == 1) 
        { 
            r += '='; 
        } 
        return r; 
    } 
 
    my.b64to256 = function(t)  
    { 
        var c, n; 
        var r = '', s = 0, a = 0; 
        var tl = t.length; 
        for (n = 0; n < tl; n++) 
        { 
            c = base64Chars.indexOf(t.charAt(n)); 
            if (c >= 0) 
            { 
                if (s) r += String.fromCharCode(a | (c >> (6 - s)) & 255); 
                s = (s + 2) & 7; 
                a = (c << s) & 255; 
            } 
        } 
        return r; 
    }     
 
    my.b16to64 = function(h) { 
        var i; 
        var c; 
        var ret = ""; 
        if(h.length % 2 == 1) 
        { 
            h = "0" + h; 
        } 
        for (i = 0; i + 3 <= h.length; i += 3) 
        { 
            c = parseInt(h.substring(i, i + 3), 16); 
            ret += base64Chars.charAt(c >> 6) + base64Chars.charAt(c & 63); 
        } 
        if (i + 1 == h.length) 
        { 
            c = parseInt(h.substring(i, i + 1), 16); 
            ret += base64Chars.charAt(c << 2); 
        } 
        else if (i + 2 == h.length) 
        { 
            c = parseInt(h.substring(i, i + 2), 16); 
            ret += base64Chars.charAt(c >> 2) + base64Chars.charAt((c & 3) << 4); 
        } 
        while ((ret.length & 3) > 0) ret += "="; 
        return ret; 
    } 
 
    my.b64to16 = function(s) { 
        var ret = ""; 
        var i; 
        var k = 0; 
        var slop; 
        for (i = 0; i < s.length; ++i) 
        { 
            if (s.charAt(i) == "=") break; 
            v = base64Chars.indexOf(s.charAt(i)); 
            if (v < 0) continue; 
            if (k == 0) 
            { 
                ret += int2char(v >> 2); 
                slop = v & 3; 
                k = 1; 
            } 
            else if (k == 1) 
            { 
                ret += int2char((slop << 2) | (v >> 4)); 
                slop = v & 0xf; 
                k = 2; 
            } 
            else if (k == 2) 
            { 
                ret += int2char(slop); 
                ret += int2char(v >> 2); 
                slop = v & 3; 
                k = 3; 
            } 
            else 
            { 
                ret += int2char((slop << 2) | (v >> 4)); 
                ret += int2char(v & 0xf); 
                k = 0; 
            } 
        } 
        if (k == 1) ret += int2char(slop << 2); 
        return ret; 
    } 
     
    // Converts a string to a byte array. 
    my.string2bytes = function(string) 
    { 
        var bytes = new Array(); 
        for(var i = 0; i < string.length; i++)  
        { 
            bytes.push(string.charCodeAt(i)); 
        } 
        return bytes; 
    } 
 
    // Converts a byte array to a string. 
    my.bytes2string = function(bytes) 
    { 
        var string = ""; 
        for(var i = 0; i < bytes.length; i++) 
        { 
            string += String.fromCharCode(bytes[i]); 
        }    
        return string; 
    } 
     
    // Returns a XOR b, where a and b are 16-byte byte arrays. 
    my.blockXOR = function(a, b) 
    { 
        var xor = new Array(16); 
        for(var i = 0; i < 16; i++) 
        { 
            xor[i] = a[i] ^ b[i]; 
        } 
        return xor; 
    } 
     
    // Returns a 16-byte initialization vector. 
    my.blockIV = function() 
    { 
        var r = new SecureRandom(); 
        var IV = new Array(16); 
        r.nextBytes(IV); 
        return IV; 
    } 
     
    // Returns a copy of bytes with zeros appended to the end 
    // so that the (length of bytes) % 16 == 0. 
    my.pad16 = function(bytes) 
    { 
        var newBytes = bytes.slice(0); 
        var padding = (16 - (bytes.length % 16)) % 16; 
        for(i = bytes.length; i < bytes.length + padding; i++) 
        { 
            newBytes.push(0); 
        } 
        return newBytes; 
    } 
     
    // Removes trailing zeros from a byte array. 
    my.depad = function(bytes) 
    { 
        var newBytes = bytes.slice(0); 
        while(newBytes[newBytes.length - 1] == 0) 
        { 
            newBytes = newBytes.slice(0, newBytes.length - 1); 
        } 
        return newBytes; 
    } 
     
     
     
     
    // AES ECB Encryption. 
    my.encryptAESECB = function(plaintext, key) 
    { 
        var exkey = key.slice(0); 
        aes.ExpandKey(exkey); 
        var blocks = my.string2bytes(plaintext); 
        blocks = my.pad16(blocks); 
        var encryptedBlocks; 
        var tempBlock; 
        for(var i = 0; i < blocks.length/16; i++) 
        { 
            if(i==0){ 
                encryptedBlocks = blocks.slice(i * 16, i * 16 + 16); 
                aes.Encrypt(encryptedBlocks, exkey); 
            }else{ 
                tempBlock = blocks.slice(i * 16, i * 16 + 16); 
                aes.Encrypt(tempBlock, exkey); 
                encryptedBlocks = encryptedBlocks.concat(tempBlock); 
            } 
        } 
        var ciphertext = my.bytes2string(encryptedBlocks); 
        return my.b256to64(ciphertext) 
    } 
 
    // AES ECB Decryption. 
    my.decryptAESECB = function(encryptedText, key) 
    { 
        var exkey = key.slice(0); 
        aes.ExpandKey(exkey); 
        var encryptedText = my.b64to256(encryptedText); 
        var encryptedBlocks = my.string2bytes(encryptedText); 
        var decryptedBlocks = new Array(); 
        for(var i = 0; i < encryptedBlocks.length/16; i++) 
        { 
            var tempBlock = encryptedBlocks.slice(i * 16, i * 16 + 16); 
            aes.Decrypt(tempBlock, exkey); 
            decryptedBlocks = decryptedBlocks.concat(tempBlock); 
        } 
        decryptedBlocks = my.depad(decryptedBlocks); 
        return my.bytes2string(decryptedBlocks); 
    } 
     
     
    // AES CBC Encryption. 
    my.encryptAESCBC = function(plaintext, key) 
    { 
        var exkey = key.slice(0); 
        aes.ExpandKey(exkey); 
        var blocks = my.string2bytes(plaintext); 
        blocks = my.pad16(blocks); 
        var encryptedBlocks = my.blockIV(); 
        for(var i = 0; i < blocks.length/16; i++) 
        { 
            var tempBlock = blocks.slice(i * 16, i * 16 + 16); 
            var prevBlock = encryptedBlocks.slice((i) * 16, (i) * 16 + 16); 
            tempBlock = my.blockXOR(prevBlock, tempBlock); 
            aes.Encrypt(tempBlock, exkey); 
            encryptedBlocks = encryptedBlocks.concat(tempBlock); 
        } 
        var ciphertext = my.bytes2string(encryptedBlocks); 
        return my.b256to64(ciphertext) 
    } 
 
    // AES CBC Decryption. 
    my.decryptAESCBC = function(encryptedText, key) 
    { 
        var exkey = key.slice(0); 
        aes.ExpandKey(exkey); 
        var encryptedText = my.b64to256(encryptedText); 
        var encryptedBlocks = my.string2bytes(encryptedText); 
        var decryptedBlocks = new Array(); 
        for(var i = 1; i < encryptedBlocks.length/16; i++) 
        { 
            var tempBlock = encryptedBlocks.slice(i * 16, i * 16 + 16); 
            var prevBlock = encryptedBlocks.slice((i-1) * 16, (i-1) * 16 + 16); 
            aes.Decrypt(tempBlock, exkey); 
            tempBlock = my.blockXOR(prevBlock, tempBlock); 
            decryptedBlocks = decryptedBlocks.concat(tempBlock); 
        } 
        decryptedBlocks = my.depad(decryptedBlocks); 
        return my.bytes2string(decryptedBlocks); 
    } 
     
    // Wraps a string to 60 characters. 
    my.wrap60 = function(string)  
    { 
        var outstr = ""; 
        for(var i = 0; i < string.length; i++) { 
            if(i % 60 == 0 && i != 0) outstr += "\n"; 
            outstr += string[i]; } 
        return outstr;  
    } 
 
    // Generate a random key for the AES-encrypted message. 
    my.generateAESKey = function() 
    { 
        var key = new Array(32); 
        var r = new SecureRandom(); 
        r.nextBytes(key); 
        return key; 
    } 
 
    return my; 
 
}()); 
 
 
 
function showE() 
{ 
    var plainText=escape(document.getElementById("textIn").value); 
    var keyForAES=document.getElementById("keyForAES").value; 
    var aesKey = cryptico.string2bytes(cryptico.b64to256( 
        "oTKD2t0WV12uyfCIsTF0+nEOTZEokqzN3r4FT61yfi8=")); 
    aesKey = cryptico.string2bytes(cryptico.b64to256( 
        cryptico.encryptAESECB(escape(keyForAES), aesKey))); 
    aesKey = aesKey.slice(0, 16); 
    var mi=cryptico.encryptAESCBC(plainText,aesKey); 
    document.getElementById("textOut").value=mi; 
} 
 
function showD() 
{ 
    var keyForAES=document.getElementById("keyForAES").value; 
    var cipherText=document.getElementById("textIn").value; 
    var aesKey = cryptico.string2bytes(cryptico.b64to256( 
        "oTKD2t0WV12uyfCIsTF0+nEOTZEokqzN3r4FT61yfi8=")); 
    aesKey = cryptico.string2bytes(cryptico.b64to256( 
        cryptico.encryptAESECB(escape(keyForAES), aesKey))); 
    aesKey = aesKey.slice(0, 16); 
    var result=cryptico.decryptAESCBC(cipherText,aesKey); 
    document.getElementById("textOut").value = unescape(result); 
} 


function showE2() 
{ 
    var plainText=escape(document.getElementById("textIn").value); 
    var keyForAES=document.getElementById("keyForAES").value; 
    var aesKey = cryptico.string2bytes(cryptico.b64to256( 
        "oTKD2t0WV12uyfCIsTF0+nEOTZEokqzN3r4FT61yfi8=")); 
    aesKey = cryptico.string2bytes(cryptico.b64to256( 
        cryptico.encryptAESECB(escape(keyForAES), aesKey))); 
    aesKey = aesKey.slice(0, 16); 
    var mi=cryptico.encryptAESECB(plainText,aesKey); 
    document.getElementById("textOut").value=mi; 
} 
 
function showD2() 
{ 
    var keyForAES=document.getElementById("keyForAES").value; 
    var cipherText=document.getElementById("textIn").value; 
    var aesKey = cryptico.string2bytes(cryptico.b64to256( 
        "oTKD2t0WV12uyfCIsTF0+nEOTZEokqzN3r4FT61yfi8=")); 
    aesKey = cryptico.string2bytes(cryptico.b64to256( 
        cryptico.encryptAESECB(escape(keyForAES), aesKey))); 
    aesKey = aesKey.slice(0, 16); 
    var result=cryptico.decryptAESECB(cipherText,aesKey); 
    document.getElementById("textOut").value = unescape(result); 
} 
             
</script>  
<div id="dd"> </div> 
<p>在下方输入密码：<br/><input type="password" name="keyForAES" id="keyForAES"></> 
<p>在下框输入要加密或者要解密的内容：<br/> 
<textarea name="textIn" rows="15" cols="50" id="textIn"></textarea></> 
<p><button style='font-size:20px' onclick="showE()">点我进行加密</button>&nbsp&nbsp 
<button style='font-size:20px' onclick="showD()">点我进行解密</button></> 
<p><button style='font-size:20px' onclick="showE2()">ECB加密</button>&nbsp&nbsp 
<button style='font-size:20px' onclick="showD2()">ECB解密</button></> 
<p>下框将会输出加密或者解密后的内容：<br/> 
<textarea name="textOut" rows="15" cols="50" id="textOut"></textarea></> 
<p id="msg"></p> 
</body> 
</html>
