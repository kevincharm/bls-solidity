import { dataSlice, hexlify, sha256, zeroPadBytes, getBytes, randomBytes } from 'ethers'
const mcl = require('mcl-wasm')
import type { G1, G2, Fr, Fp, Fp2 } from 'mcl-wasm'

/**
 * Mcl wrapper
 * Mostly copied from: https://github.com/kilic/evmbls
 */
export class Mcl {
    static readonly FIELD_ORDER =
        0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47n

    private _domain: Uint8Array
    public readonly G1: G1
    public readonly G2: G2

    private constructor(public readonly domain: string) {
        this._domain = Uint8Array.from(Buffer.from(domain, 'utf-8'))
        this.G1 = new mcl.G1()
        this.G1.setStr('0x01 0x02')
        this.G2 = new mcl.G2()
        const g2x = createFp2(
            '0x1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed',
            '0x198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2',
        )
        const g2y = createFp2(
            '0x12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa',
            '0x090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b',
        )
        const g2z = createFp2('0x01', '0x00')
        this.G2.setX(g2x)
        this.G2.setY(g2y)
        this.G2.setZ(g2z)
    }

    public static async create(domain: string) {
        await mcl.init(mcl.BN_SNARK1)
        mcl.setETHserialization(true)
        mcl.setMapToMode(1)
        return new Mcl(domain)
    }

    private mapToPoint(eHex: `0x${string}`) {
        const e0 = BigInt(eHex)
        let e1: Fp = new mcl.Fp()
        e1.setStr(mod(e0, Mcl.FIELD_ORDER).toString())
        return e1.mapToG1()
    }

    private expandMsg(domain: Uint8Array, msg: Uint8Array, outLen: number): Uint8Array {
        if (domain.length > 255) {
            throw new Error('bad domain size')
        }

        const out: Uint8Array = new Uint8Array(outLen)

        const len0 = 64 + msg.length + 2 + 1 + domain.length + 1
        const in0: Uint8Array = new Uint8Array(len0)
        // zero pad
        let off = 64
        // msg
        in0.set(msg, off)
        off += msg.length
        // l_i_b_str
        in0.set([(outLen >> 8) & 255, outLen & 255], off)
        off += 2
        // I2OSP(0, 1)
        in0.set([0], off)
        off += 1
        // DST_prime
        in0.set(domain, off)
        off += domain.length
        in0.set([domain.length], off)

        const b0 = sha256(in0)

        const len1 = 32 + 1 + domain.length + 1
        const in1: Uint8Array = new Uint8Array(len1)
        // b0
        in1.set(getBytes(b0), 0)
        off = 32
        // I2OSP(1, 1)
        in1.set([1], off)
        off += 1
        // DST_prime
        in1.set(domain, off)
        off += domain.length
        in1.set([domain.length], off)

        const b1 = sha256(in1)

        // b_i = H(strxor(b_0, b_(i - 1)) || I2OSP(i, 1) || DST_prime);
        const ell = Math.floor((outLen + 32 - 1) / 32)
        let bi = b1

        for (let i = 1; i < ell; i++) {
            const ini: Uint8Array = new Uint8Array(32 + 1 + domain.length + 1)
            const nb0 = getBytes(zeroPadBytes(getBytes(b0), 32))
            const nbi = getBytes(zeroPadBytes(getBytes(bi), 32))
            const tmp = new Uint8Array(32)
            for (let i = 0; i < 32; i++) {
                tmp[i] = nb0[i] ^ nbi[i]
            }

            ini.set(tmp, 0)
            let off = 32
            ini.set([1 + i], off)
            off += 1
            ini.set(domain, off)
            off += domain.length
            ini.set([domain.length], off)

            out.set(getBytes(bi), 32 * (i - 1))
            bi = sha256(ini)
        }

        out.set(getBytes(bi), 32 * (ell - 1))
        return out
    }

    private hashToField(domain: Uint8Array, msg: Uint8Array, count: number): bigint[] {
        const u = 48
        const _msg = this.expandMsg(domain, msg, count * u)
        const els = []
        for (let i = 0; i < count; i++) {
            const el = mod(BigInt(hexlify(_msg.slice(i * u, (i + 1) * u))), Mcl.FIELD_ORDER)
            els.push(el)
        }
        return els
    }

    public hashToPoint(msg: `0x${string}`) {
        const _msg = Uint8Array.from(Buffer.from(msg.slice(2), 'hex'))
        const hashRes = this.hashToField(this._domain, _msg, 2)
        const e0 = hashRes[0]
        const e1 = hashRes[1]
        const p0 = this.mapToPoint(toHex(e0))
        const p1 = this.mapToPoint(toHex(e1))
        const p = mcl.add(p0, p1)
        p.normalize()
        return p
    }

    public serialiseFp(p: Fp | Fp2): `0x${string}` {
        // NB: big-endian
        return ('0x' +
            Array.from(p.serialize())
                .reverse()
                .map((value) => value.toString(16).padStart(2, '0'))
                .join('')) as `0x${string}`
    }

    public serialiseG1Point(p: G1): [bigint, bigint] {
        p.normalize()
        const x = BigInt(this.serialiseFp(p.getX()))
        const y = BigInt(this.serialiseFp(p.getY()))
        return [x, y]
    }

    public serialiseG2Point(p: G2): [bigint, bigint, bigint, bigint] {
        const x = this.serialiseFp(p.getX())
        const y = this.serialiseFp(p.getY())
        return [
            BigInt(dataSlice(x, 32)),
            BigInt(dataSlice(x, 0, 32)),
            BigInt(dataSlice(y, 32)),
            BigInt(dataSlice(y, 0, 32)),
        ]
    }

    public createKeyPair() {
        const secretKey: Fr = new mcl.Fr()
        secretKey.setHashOf(hexlify(randomBytes(12)))
        const pubKey: G2 = mcl.mul(this.G2, secretKey)
        pubKey.normalize()
        return {
            secretKey,
            pubKey,
        }
    }

    public sign(msg: `0x${string}`, secret: Fr) {
        const M: G1 = this.hashToPoint(msg)
        const signature: G1 = mcl.mul(M, secret)
        signature.normalize()
        return {
            signature,
            M,
        }
    }

    public toArgs(pubKey: G2, M: G1, signature: G1) {
        return {
            signature: this.serialiseG1Point(signature),
            pubKey: this.serialiseG2Point(pubKey),
            M: this.serialiseG1Point(M),
        }
    }
}

function mod(a: bigint, b: bigint) {
    return ((a % b) + b) % b
}

function toHex(n: bigint): `0x${string}` {
    return ('0x' + n.toString(16).padStart(64, '0')) as `0x${string}`
}

function createFp2(a: string, b: string) {
    const fp2_a: Fp = new mcl.Fp()
    const fp2_b: Fp = new mcl.Fp()
    fp2_a.setStr(a)
    fp2_b.setStr(b)
    const fp2: Fp2 = new mcl.Fp2()
    fp2.set_a(fp2_a)
    fp2.set_b(fp2_b)
    return fp2
}
