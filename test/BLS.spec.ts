import { ethers } from 'hardhat'
import { TestBLS, TestBLS__factory } from '../typechain-types'
import { SignerWithAddress } from '@nomicfoundation/hardhat-ethers/signers'
import { getBytes, hexlify, keccak256, toUtf8Bytes } from 'ethers'
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
        const msg = keccak256(roundNumber) as `0x${string}`
        const [msgX, msgY] = await testBLS.hashToPoint(msg)
        const M = mcl.g1FromEvm(msgX, msgY)
        expect(M.isValid()).to.eq(true)
        // console.log('M', kyberMarshalG1(M))
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
            '1fc4480c175f548c833b247c17c34ff0fdb286f6dd7933a9b649b2fd778942ab305885d193f3b76b8bcf543ca39ea156cc7b689bf5c8a611ecc734c083e346d72e7d96a13f08bf919c79482ff98df9e9d3c54a2dc41544f96aac67973a7c9e520844614c812c7b9b02734249ebc685f95c461354066db0235fb4f6d5f66d6eab'
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
                    '2f4ecd92eb8ed2cbf68da23414381904dab56c5b0636aa3ed9178775817445262ec396f22c1322f6c7242248c2a0f5036ee0e310b1b8e8c38244424734e4338c',
                randomness: 'c0a5752cb3035f5e722879964e3bf8ad208ec13d99f55cd19ea50a3d04a06f66',
            },
            {
                round: 8,
                signature:
                    '10143eec9d9e2cbe214e959ce07b3d9377d6cf1f7d341a162e6e3efdfe7527d90c3fb1bdacbe74177d9ba25a01de4f960315cf54b42329c4ce3be1671a7cb6aa',
                randomness: 'd11adb5ffe269df0a0dbc3f1b2f6ea610637d869591af5c0498ca302dd4ecb85',
            },
            {
                round: 9,
                signature:
                    '1c0c87301cb2dcd36760a762a8ce11b88c5bb844e8ce31344e17c66c18ecd5c812b40d12ddb706d605ded256295fcde47f7858777b5dfe304b064dbda02e9d14',
                randomness: '8bb96871a83867cc0a1c319e4b3180efaa9e095f4e687f500a92d82832627eee',
            },
            // After reshare
            {
                round: 14,
                signature:
                    '2867f7e263be6b0dbc4af6e373e77e336c3844f84c51be5dbb3e79df190c2dfe1cf438579230b4530010c5da6c29f62ebfa7d1a99dfb478d19a26c90a301b6f5',
                randomness: '8d10e4c3031511293b4b96b6e4e9af53b80b37028a16aa40d07e434fb5e576d3',
            },
            {
                round: 15,
                signature:
                    '085073c1106e18d7c32ffd6330c27cfae45a92ee8fbf76d5154a8d0c09e9855f2752e37a094aff403ff0e3507609dd1156822864c1ee45e5742c6fffa0630755',
                randomness: '468183d47948a1ee477f326c8fcbbcd76773c0dc62cfc991b295401e1e81262a',
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
            const M = await testBLS.hashToPoint(keccak256(roundNumber))

            expect(await testBLS.verifySingle(sig, pk, [M[0], M[1]])).to.eq(true)
        }
    })
})
