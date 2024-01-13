import * as kp from './index.mjs'
import assert from 'assert'

const random_string = (len) => {
    const chars = 'ABCDEFGHIJKLM NOPQRSTUVWXYZ abcdefghijklm nopqrstuvwxyz 01234 56789'
    let result = '';
    const len_chars = chars.length;
    for (let i = 0; i < len; i++) {
        result += chars.charAt(Math.floor(Math.random() * len_chars));
    }
    return result;
}

/**
 * async test
 */
(async () => {
    const sk = kp.sk()
    const vk = await kp.vk_async(sk)
    console.log(`len=${sk.length} sk=${sk}`)
    console.log(`len=${vk.length} vk=${vk}`)
    const message = random_string(50)
    console.log(`len=${message.length} message=${message}`)
    const signature = await kp.sign_async(message, sk)
    console.log(`len=${signature.length} signature=${signature}`)
    const res = await kp.verify_async(signature, message, vk)
    assert.strictEqual(res, true)
})()

/**
 * sync test
 */
const sk = kp.sk()
const vk = kp.vk(sk)
console.log(`len=${sk.length} sk=${sk}`)
console.log(`len=${vk.length} vk=${vk}`)
const message = random_string(50)
console.log(`len=${message.length} message=${message}`)
const signature = kp.sign(message, sk)
console.log(`len=${signature.length} signature=${signature}`)
const res = kp.verify(signature, message, vk)
assert.strictEqual(res, true)