import { ethers } from 'hardhat'
import { TestBLS, TestBLS__factory } from '../typechain-types'
import { SignerWithAddress } from '@nomicfoundation/hardhat-ethers/signers'
import { getBytes, hexlify, sha256, toUtf8Bytes } from 'ethers'
import { expect } from 'chai'
import { Mcl, byteSwap, kyberMarshalG1, kyberMarshalG2 } from '../lib/Mcl'

describe('BLS', () => {
    let mcl: Mcl
    before(async () => {
        mcl = await Mcl.create('testing evmbls')
    })

    let testBLS: TestBLS
    let deployer: SignerWithAddress
    beforeEach(async () => {
        ;[deployer] = await ethers.getSigners()
        testBLS = await new TestBLS__factory(deployer).deploy()
    })

    it('verify single', async () => {
        const { secretKey, pubKey } = mcl.createKeyPair()
        // const msg = hexlify(randomBytes(12)) as `0x${string}`
        // 64-bit round number, encoded in big-endian
        const roundNumber = new Uint8Array(8)
        roundNumber[7] = 1 // round = 1
        const msg = sha256(roundNumber) as `0x${string}`
        const [msgX, msgY] = await testBLS.hashToPoint(msg)
        const M = mcl.g1EvmToKyberMarshal(msgX, msgY)
        expect(M.isValid()).to.eq(true)
        const { signature } = mcl.sign(M, secretKey)

        // Kyber serialised format
        // console.log('pub', kyberMarshalG2(pubKey))
        // console.log('sig', kyberMarshalG1(signature))

        const args = mcl.toArgs(pubKey, M, signature)
        expect(await testBLS.isOnCurveG1(args.signature)).to.eq(true) // 400 gas
        expect(await testBLS.isOnCurveG1(args.M)).to.eq(true) // 400 gas
        expect(await testBLS.isOnSubgroupG2DLZZ(args.pubKey)).to.eq(true) // 865k gas
        expect(await testBLS.verifySingle(args.signature, args.pubKey, args.M)).to.eq(true)
        console.log('gas:', await testBLS.verifySingleGasCost(args.signature, args.pubKey, args.M))
    })

    it('drand outputs', async () => {
        const groupPubKey =
            '1efb918825c4cdcac04fe1d8160fb7ccf026f5310007cfeb79a88fa230a862bf10372536548a0cb7e2571f8e8109ea21e2e4e50c9c0c2c90f4ebac592c71ba5f086bfb9f31223fe529d8cb0838f36c9e3dfc24c8c1489b6ebd5f2d4d8aa751e80df9a8b0c0fd607fadf01f842c2b07c7c46a9fd9de32a71054f669fc247bb63d'
        const pkBytes = getBytes(`0x${groupPubKey}`)
        const pk = [
            pkBytes.slice(32, 64),
            pkBytes.slice(0, 32),
            pkBytes.slice(96, 128),
            pkBytes.slice(64, 96),
        ].map((pkBuf) => BigInt(hexlify(pkBuf))) as [bigint, bigint, bigint, bigint]
        const testVectors = [
            {
                round: 5,
                signature:
                    '0546626efc3055fe50f1cd394aa4e358ef2dad8f53f22e996506f792cd6042d613c94f26099560e98d16b9dff40801e8299c1ef74dafa2f3368f80c8e614f76c',
                randomness: 'ba3b883927bba42bea84206a50dfcabdbb8a9f66c7a4a14697a55fb7cbb3854c',
            },
            {
                round: 8,
                signature:
                    '1627f48160ecb4587364f4b1cf5ae2bb0875cc894f548443f57325971dccbe340972b4169bfb9512670e96e5dae1416ae8c3c494120a2b267c158f54feef08ff',
                randomness: '04af8b2a9aa1358f2121f50955ea58d2706fea54b1b5ed72c6932a51ca9cc8e9',
            },
            {
                round: 14,
                signature:
                    '2e7579d942fe474f98a9a9ebfb80eef38901946128f7fd03a8c452a5104bf06e128b22a810ea9c2055a57421be2180862c79a278f2e357d9f89f3f8cf9560c46',
                randomness: 'd15f7b7f6b01c2b82ec2229deaf12ec54ce37708b4f29cc17e59fae13806aae9',
            },
            // After reshare
            {
                round: 42,
                signature:
                    '0b68100f3fc754ade870943ac6e83cea5e7f264fbf20f764002e9cb53c2176f51cf14a0b9a4ded00e7710471eed339d5eac09968ec863e947c9d5cd13420871d',
                randomness: '2dbb439b460ee3137e50d9191edbb6e94b9692a8bfb84e17fae21a62fcc91b18',
            },
            {
                round: 45,
                signature:
                    '18ecae5d3bd5c1b163c12088f5fb8bb63ab6bad6bdf307b9272bc094af6463390d5c48414afe743b15a5ee0251f622452caa92a8a9132ab9b36d42546a60fe93',
                randomness: '4cae4c56a81f3fe7e56535b18c9210bf73c63f9341a933a4fed39636f08dade3',
            },
        ]
        for (const { round, signature, randomness } of testVectors) {
            const sigBytes = getBytes(`0x${signature}`)
            const sig = [sigBytes.slice(0, 32), sigBytes.slice(32, 64)].map((sigBuf) =>
                BigInt(hexlify(sigBuf)),
            ) as [bigint, bigint]

            // Round number must be interpreted as a uint64, then fed into sha256
            const roundNumber = new Uint8Array(8)
            roundNumber[7] = round
            const M = await testBLS.hashToPoint(sha256(roundNumber))

            expect(await testBLS.verifySingle(sig, pk, [M[0], M[1]])).to.eq(true)
        }
    })
})
