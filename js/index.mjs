import * as ed from '@noble/ed25519'
import {sha512} from '@noble/hashes/sha512'
ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m))

/**
 * generate signing key
 * @returns signing_key String(Hex)
 */
export const sk = () => ed.etc.bytesToHex(ed.utils.randomPrivateKey())

/**
 * generate verifying key
 * @param {*} signing_key String(Hex)
 * @returns verifying_key String(Hex)
 */
export const vk = (signing_key) => {
    // console.log(`[js] vk signing_key=${signing_key}`)
    const k = ed.etc.bytesToHex(ed.getPublicKey(signing_key))
    // console.log(`[js] vk k=${k}`)
    return k
}

/**
 * async vk function
 */
export const vk_async = async (signing_key) => {
    // console.log(`[js] vk signing_key=${signing_key}`)
    const k = ed.etc.bytesToHex(await ed.getPublicKeyAsync(signing_key))
    // console.log(`[js] vk k=${k}`)
    return k
}

/**
 * sign message
 * @param {*} message     String(UTF16)
 * @param {*} signing_key String(Hex) 
 * @returns signature     String(Hex)
 */
export const sign = (message, signing_key) => {
    const bytes = new TextEncoder().encode(message)
    return ed.etc.bytesToHex(ed.sign(bytes, signing_key))
}

/**
 * async sign function
 */
export const sign_async = async (message, signing_key) => {
    const bytes = new TextEncoder().encode(message)
    return ed.etc.bytesToHex(await ed.signAsync(bytes, signing_key))
}

/**
 * verify message
 * @param {*} signature     String(Hex)
 * @param {*} message       String(UTF16)
 * @param {*} verifying_key String(Hex)
 * @returns yes_no boolean
 */
export const verify = (signature, message, verifying_key) => {
    const bytes = new TextEncoder().encode(message)
    return ed.verify(signature, bytes, verifying_key)
}

/**
 * async verify function
 */
export const verify_async = async (signature, message, verifying_key) => {
    const bytes = new TextEncoder().encode(message)
    return await ed.verifyAsync(signature, bytes, verifying_key)
}

// for integration test
// console.log(`[js] process.argv.length=${process.argv.length}`)
if (process.argv.length > 2) {
    (async () => {
        let res
        switch(process.argv[2]) {
            case 'sk':     
                res = sk(); break;
            case 'vk':     
                res = await vk_async(process.argv[3]);  break;
            case 'sign':   
                res = await sign_async(process.argv[3], process.argv[4]); break;
            case 'verify': 
                res = await verify_async(process.argv[3], process.argv[4], process.argv[5]); break;
            default:     
                res = '';
        }
        // log out stdout for integration test
        console.log(res)
    })()
}